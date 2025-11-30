using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SecureAuthDemo.Web.Admin
{
    /// <summary>
    /// Sensitive admin page that requires two-factor authentication to access.
    /// Demonstrates custom authorization policy enforcement for MFA.
    /// </summary>
    [Authorize(Policy = "RequireTwoFactorEnabled")]
    public class SensitiveSettingsModel : PageModel
    {
        public void OnGet()
        {
            // Page content is protected by the RequireTwoFactorEnabled policy
            // Only users with TwoFactorEnabled == true can access this page
        }
    }
}
