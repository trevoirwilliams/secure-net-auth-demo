using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace SecureAuthDemo.Web.Authorization
{
    /// <summary>
    /// Authorization handler that checks if the current user has two-factor authentication enabled.
    /// Used with the "RequireTwoFactorEnabled" policy to protect sensitive pages.
    /// </summary>
    public class TwoFactorRequirementHandler : AuthorizationHandler<TwoFactorRequirement>
    {
        private readonly UserManager<IdentityUser> _userManager;

        public TwoFactorRequirementHandler(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        protected override async Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            TwoFactorRequirement requirement)
        {
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                context.Fail();
                return;
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                context.Fail();
                return;
            }

            // Check if the user has 2FA enabled
            if (user.TwoFactorEnabled)
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail();
            }
        }
    }
}
