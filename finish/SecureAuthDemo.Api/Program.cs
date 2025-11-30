using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SecureAuthDemo.Api.Auth;
using SecureAuthDemo.Api.Configuration;
using SecureAuthDemo.Api.Data;
using SecureAuthDemo.Api.Domain;
using SecureAuthDemo.Api.Dtos;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Config: DbContext (SQLite)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Data Source=secureauthdemo.db";

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(connectionString));

builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.User.RequireUniqueEmail = true;
})  .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// JWT Auth (intentionally missing strict issuer/audience validation for demo)
var jwtSection = builder.Configuration.GetSection("Jwt");
var key = jwtSection["Key"] ?? string.Empty;

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
        ValidateIssuer = true, // Should validate issuer
        ValidateAudience = true, // Should validate audience
        ValidateLifetime = true, // Accepts expired tokens (teaching sample)
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

builder.Services.AddSingleton<ITokenService, TokenService>();

var app = builder.Build();

// Ensure database created and migrations applied
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    db.Database.Migrate();
    // Seed Admin role/user for demo purposes
    try
    {
        IdentitySeeder.SeedAdminAsync(scope.ServiceProvider).GetAwaiter().GetResult();
    }
    catch
    {
        // Intentionally swallow for demo; avoid leaking details
    }
}

app.MapGet("/", () => Results.Ok(new { message = "SecureAuthDemo.Api running" }));

// Auth endpoints
app.MapPost("/api/auth/register", async (
    RegisterRequest req,
    UserManager<IdentityUser> userManager,
    ApplicationDbContext db) =>
{
    var user = new IdentityUser { UserName = req.Email, Email = req.Email };
    var result = await userManager.CreateAsync(user, req.Password);

    if (!result.Succeeded)
    {
        var errors = result.Errors.Select(e => e.Description).ToArray();
        return Results.ValidationProblem(errors.ToDictionary(e => e, e => new[] { e }));
    }

    await SampleDataSeeder.SeedOrdersForUserAsync(db, user.Id);

    return Results.Created($"/api/users/{user.Id}", new { user.Id, user.Email });
});

app.MapPost("/api/auth/login", async (
    LoginRequest req,
    UserManager<IdentityUser> userManager,
    SignInManager<IdentityUser> signInManager,
    ITokenService tokenService) =>
{
    var user = await userManager.FindByEmailAsync(req.Email);
    if (user is null)
    {
        return Results.BadRequest(new { error = "Invalid credentials" });
    }

    var passwordValid = await userManager.CheckPasswordAsync(user, req.Password);
    if (!passwordValid)
        return Results.BadRequest(new { error = "Invalid credentials" });

    var roles = await userManager.GetRolesAsync(user);
    var token = tokenService.CreateToken(user, roles);

    return Results.Ok(new
    {
        access_token = token,
        user = new { user.Id, user.Email, roles }
    });
});

// Orders endpoints
app.MapGet("/api/orders", async (
    ClaimsPrincipal principal,
    ApplicationDbContext db) =>
{
    var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(userId)) return Results.Unauthorized();

    var orders = await db.Orders
        .Where(o => o.OwnerUserId == userId)
        .OrderByDescending(o => o.CreatedAt)
        .Select(o => new { o.Id, o.OrderNumber, o.Total, o.CreatedAt })
        .ToListAsync();

    return Results.Ok(orders);
}).RequireAuthorization();

app.MapGet("/api/orders/{id:int}", async (
    int id,
    ClaimsPrincipal principal,
    ApplicationDbContext db) =>
{
    var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(userId)) return Results.Unauthorized();

    var order = await db.Orders
        .Where(o => o.Id == id && o.OwnerUserId == userId)
        .Select(o => new { o.Id, o.OrderNumber, o.Total, o.CreatedAt })
        .FirstOrDefaultAsync();

    return order is null ? Results.NotFound() : Results.Ok(order);
}).RequireAuthorization();

// Admin endpoint (stubbed policy requiring Admin role)
app.MapGet("/api/admin/orders", async (ApplicationDbContext db) =>
{
    var orders = await db.Orders
        .OrderByDescending(o => o.CreatedAt)
        .ToListAsync();
    return Results.Ok(orders);
}).RequireAuthorization("AdminOnly");

// INCORRECT: Custom insecure login bypassing Identity & proper hashing
// Demonstrates multiple bad practices: plaintext password check, hardcoded users/roles
app.MapPost("/api/auth/insecure-login", (
    LoginRequest req,
    ITokenService tokenService) =>
{
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { error = "Email and Password are required" });

    if (!InsecureAuthStore.ValidateCredentials(req.Email, req.Password))
    {
        return Results.BadRequest(new { error = "Invalid credentials (insecure endpoint)" });
    }

    var roles = InsecureAuthStore.GetRoles(req.Email);
    // INCORRECT: Fabricated IdentityUser without store
    var fakeUser = new IdentityUser { Id = Guid.NewGuid().ToString(), UserName = req.Email, Email = req.Email };
    var token = tokenService.CreateToken(fakeUser, roles);
    return Results.Ok(new { access_token = token, user = new { fakeUser.Id, fakeUser.Email, roles }, insecure = true });
});

// INCORRECT: Missing HTTPS redirection middleware (app.UseHttpsRedirection())
// In production, transport security MUST be enforced.

app.Run();
