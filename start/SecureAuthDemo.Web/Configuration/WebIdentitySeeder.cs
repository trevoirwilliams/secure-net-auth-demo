using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SecureAuthDemo.Web.Data;

namespace SecureAuthDemo.Web.Configuration
{
    public static class WebIdentitySeeder
    {
        public static async Task SeedAsync(IServiceProvider services)
        {
            using var scope = services.CreateScope();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var db = scope.ServiceProvider.GetRequiredService<WebApplicationDbContext>();

            const string roleName = "Admin";
            const string adminEmail = "webadmin@example.com";
            const string adminPassword = "Admin123!"; // For demo only; move to secrets later

            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new IdentityRole(roleName));
            }

            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            if (adminUser == null)
            {
                adminUser = new IdentityUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    EmailConfirmed = true
                };

                var createResult = await userManager.CreateAsync(adminUser, adminPassword);
                if (!createResult.Succeeded)
                {
                    return; // Keep silent for demo; avoid logging sensitive details
                }
            }

            if (!await userManager.IsInRoleAsync(adminUser, roleName))
            {
                await userManager.AddToRoleAsync(adminUser, roleName);
            }
        }
    }
}
