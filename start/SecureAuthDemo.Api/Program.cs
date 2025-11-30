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

// Identity with relaxed password requirements for teaching
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Password.RequiredLength = 6;
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    // INCORRECT: Disabling lockout reduces protection against brute-force
    options.Lockout.AllowedForNewUsers = false; // Demonstrates weak brute-force protection
})
.AddEntityFrameworkStores<ApplicationDbContext>()
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
        ValidateIssuer = false, // INCORRECT: Should validate issuer
        ValidateAudience = false, // INCORRECT: Should validate audience
        ValidateLifetime = false, // INCORRECT: Accepts expired tokens (teaching sample)
        ClockSkew = TimeSpan.Zero
    };
    // INCORRECT: Allowing non-HTTPS metadata fetching
    options.RequireHttpsMetadata = false; // Should be true in production
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
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { error = "Email and Password are required" });

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
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { error = "Email and Password are required" });

    var user = await userManager.FindByEmailAsync(req.Email);
    if (user is null)
    {
        // INCORRECT: Leaky error message reveals user does not exist
        return Results.BadRequest(new { error = "User does not exist" });
    }

    var passwordValid = await userManager.CheckPasswordAsync(user, req.Password);
    if (!passwordValid)
        // INCORRECT: Leaky error message reveals password invalid vs. user not found
        return Results.BadRequest(new { error = "Invalid password" });

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
        // INCORRECT: Verbose error helps attackers enumerate valid accounts
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
