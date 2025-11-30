using Microsoft.AspNetCore.Authorization;

namespace SecureAuthDemo.Web.Authorization
{
    /// <summary>
    /// Requirement that the authenticated user must have two-factor authentication enabled.
    /// Used to protect sensitive pages that should only be accessible with MFA.
    /// </summary>
    public class TwoFactorRequirement : IAuthorizationRequirement
    {
    }
}
