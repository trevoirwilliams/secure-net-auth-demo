using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace SecureAuthDemo.Web.Data
{
    public class WebApplicationDbContext : IdentityDbContext<IdentityUser>
    {
        public WebApplicationDbContext(DbContextOptions<WebApplicationDbContext> options) : base(options)
        {
        }
    }
}
