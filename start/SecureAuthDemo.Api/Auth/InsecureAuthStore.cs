// INCORRECT: This class demonstrates several insecure practices.
// - Hardcoded users with PLAINTEXT passwords
// - Bypasses ASP.NET Core Identity completely
// - Intended ONLY for teaching what NOT to do.
// DO NOT replicate in real applications.
namespace SecureAuthDemo.Api.Auth
{
    public class InsecureAuthStore
    {
        // INCORRECT: Plaintext credential storage (should use strong hashing & Identity)
        private static readonly Dictionary<string, string> _users = new()
        {
            { "insecure.user@example.com", "password123" },
            { "test@example.com", "test" }
        };

        // INCORRECT: Hardcoded roles and claims
        private static readonly Dictionary<string, string[]> _roles = new()
        {
            { "insecure.user@example.com", new [] { "User" } },
            { "test@example.com", new [] { "User", "Admin" } }
        };

        public static bool ValidateCredentials(string email, string password)
        {
            return _users.TryGetValue(email, out var stored) && stored == password; // INCORRECT: Plain equality check
        }

        public static IEnumerable<string> GetRoles(string email)
        {
            return _roles.TryGetValue(email, out var r) ? r : Array.Empty<string>();
        }
    }
}
