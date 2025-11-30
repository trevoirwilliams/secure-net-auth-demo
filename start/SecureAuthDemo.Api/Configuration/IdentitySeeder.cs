using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SecureAuthDemo.Api.Data;

namespace SecureAuthDemo.Api.Configuration
{
    public static class IdentitySeeder
    {
        public static async Task SeedAdminAsync(IServiceProvider services)
        {
            using var scope = services.CreateScope();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            const string adminRole = "Admin";
            const string adminEmail = "admin@example.com";
            const string adminPassword = "Admin123!"; // For demo only; move to secrets later

            if (!await roleManager.RoleExistsAsync(adminRole))
            {
                await roleManager.CreateAsync(new IdentityRole(adminRole));
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
                    return; // Keep silent for demo; no logging of sensitive info
                }
            }

            if (!await userManager.IsInRoleAsync(adminUser, adminRole))
            {
                await userManager.AddToRoleAsync(adminUser, adminRole);
            }

            await SampleDataSeeder.SeedOrdersForUserAsync(db, adminUser.Id);
        }
    }
}
