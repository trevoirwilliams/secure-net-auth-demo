using Microsoft.AspNetCore.Identity;

namespace SecureAuthDemo.Api.Auth
{
    public interface ITokenService
    {
        string CreateToken(IdentityUser user, IEnumerable<string> roles);
    }
}
