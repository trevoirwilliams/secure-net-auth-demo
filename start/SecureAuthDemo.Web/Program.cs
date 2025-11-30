// SecureAuthDemo.Web
// 
// This Razor Pages application demonstrates:
// - ASP.NET Core Identity with TOTP-based multi-factor authentication (MFA).
// - Uses its own separate Identity database (secureauthdemo-web.db).
// - Identity UI pages for enabling authenticator app, viewing/generating recovery codes.
// - Custom authorization policy (RequireTwoFactorEnabled) to protect sensitive admin pages.
//
// Key MFA flows:
// - Enable authenticator app: /Identity/Account/Manage/EnableAuthenticator
// - View/generate recovery codes: /Identity/Account/Manage/ShowRecoveryCodes, GenerateRecoveryCodes
// - Access MFA-protected content: /Admin/SensitiveSettings (requires 2FA enabled)

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureAuthDemo.Web.Data;
using SecureAuthDemo.Web.Authorization;
using SecureAuthDemo.Web.Configuration;

var builder = WebApplication.CreateBuilder(args);

// Use separate WebApplicationDbContext with its own SQLite database
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Data Source=secureauthdemo-web.db";

builder.Services.AddDbContext<WebApplicationDbContext>(options =>
    options.UseSqlite(connectionString));

// Configure ASP.NET Core Identity with TOTP MFA support
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    // Relaxed password policy for teaching (keep consistent with API)
    options.Password.RequiredLength = 6;
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;

    // Sign-in configuration for MFA
    options.SignIn.RequireConfirmedAccount = false; // For demo; set true for email confirmation
    options.SignIn.RequireConfirmedEmail = false;   // Can be enabled for production

    // Enable token providers for TOTP
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
})
.AddEntityFrameworkStores<WebApplicationDbContext>()
.AddDefaultTokenProviders()
.AddDefaultUI(); // Adds the default Identity UI (login, register, manage, etc.)

// Custom authorization policy: require 2FA enabled
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireTwoFactorEnabled", policy =>
        policy.Requirements.Add(new TwoFactorRequirement()));
});

builder.Services.AddScoped<IAuthorizationHandler, TwoFactorRequirementHandler>();

builder.Services.AddRazorPages();

var app = builder.Build();

// Apply migrations and seed default Web role/user
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var db = services.GetRequiredService<WebApplicationDbContext>();
        db.Database.Migrate();
        WebIdentitySeeder.SeedAsync(services).GetAwaiter().GetResult();
    }
    catch
    {
        // Swallow for demo; avoid leaking details
    }
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // INCORRECT: Missing app.UseHsts() for teaching demo
}

// INCORRECT: Missing app.UseHttpsRedirection() for teaching demo
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();
