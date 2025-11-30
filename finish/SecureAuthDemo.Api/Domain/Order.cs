using System;

namespace SecureAuthDemo.Api.Domain
{
    public class Order
    {
        public int Id { get; set; }
        public string OrderNumber { get; set; } = string.Empty;
        public decimal Total { get; set; }
        public DateTime CreatedAt { get; set; }
        public string OwnerUserId { get; set; } = string.Empty;
    }
}
