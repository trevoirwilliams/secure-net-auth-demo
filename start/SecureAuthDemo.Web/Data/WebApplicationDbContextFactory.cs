using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SecureAuthDemo.Web.Data
{
    public class WebApplicationDbContextFactory : IDesignTimeDbContextFactory<WebApplicationDbContext>
    {
        public WebApplicationDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<WebApplicationDbContext>();
            optionsBuilder.UseSqlite("Data Source=secureauthdemo-web.db");

            return new WebApplicationDbContext(optionsBuilder.Options);
        }
    }
}
