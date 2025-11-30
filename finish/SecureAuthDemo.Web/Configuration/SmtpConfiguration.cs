namespace SecureAuthDemo.Web.Configuration
{
    public class SmtpConfiguration
    {
        public string? Host { get; set; } = "localhost";
        public int Port { get; set; } = 25;
        public bool EnableSsl { get; set; } = false;
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? From { get; set; } = "no-reply@example.com";
    }
}