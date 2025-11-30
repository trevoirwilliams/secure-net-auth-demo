using SecureAuthDemo.Api.Data;
using SecureAuthDemo.Api.Domain;

namespace SecureAuthDemo.Api.Configuration
{
    public static class SampleDataSeeder
    {
        public static async Task SeedOrdersForUserAsync(ApplicationDbContext db, string userId)
        {
            if (string.IsNullOrWhiteSpace(userId)) return;

            // Only add if the user has no orders
            if (db.Orders.Any(o => o.OwnerUserId == userId)) return;

            var now = DateTime.UtcNow;
            var orders = new List<Order>
            {
                new Order { OrderNumber = $"ORD-{now:yyyyMMdd}-001", Total = 49.99m, CreatedAt = now.AddDays(-3), OwnerUserId = userId },
                new Order { OrderNumber = $"ORD-{now:yyyyMMdd}-002", Total = 19.00m, CreatedAt = now.AddDays(-2), OwnerUserId = userId },
                new Order { OrderNumber = $"ORD-{now:yyyyMMdd}-003", Total = 199.95m, CreatedAt = now.AddDays(-1), OwnerUserId = userId }
            };

            db.Orders.AddRange(orders);
            await db.SaveChangesAsync();
        }
    }
}
