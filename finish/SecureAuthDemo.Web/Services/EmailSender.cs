using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Options;
using SecureAuthDemo.Web.Configuration;
using MailKit.Net.Smtp;
using MimeKit;

namespace SecureAuthDemo.Web.Services
{
    // Production-ready (dev-friendly) IEmailSender using MailKit for async sends.
    public class EmailSender : IEmailSender
    {
        private readonly SmtpConfiguration _config;

        public EmailSender(IOptions<SmtpConfiguration> config)
        {
            _config = config.Value;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var message = new MimeMessage();
            var from = _config.From ?? "no-reply@example.com";
            message.From.Add(MailboxAddress.Parse(from));
            message.To.Add(MailboxAddress.Parse(email));
            message.Subject = subject;

            var bodyBuilder = new BodyBuilder { HtmlBody = htmlMessage };
            message.Body = bodyBuilder.ToMessageBody();

            try
            {
                using var client = new SmtpClient();
                // Papercut/dev servers typically don't use SSL or auth
                if (_config.EnableSsl)
                {
                    await client.ConnectAsync(_config.Host, _config.Port, MailKit.Security.SecureSocketOptions.StartTlsWhenAvailable);
                }
                else
                {
                    await client.ConnectAsync(_config.Host, _config.Port, MailKit.Security.SecureSocketOptions.None);
                }

                if (!string.IsNullOrEmpty(_config.Username))
                {
                    await client.AuthenticateAsync(_config.Username!, _config.Password!);
                }

                await client.SendAsync(message);
                await client.DisconnectAsync(true);
            }
            catch
            {
                // Swallowing for demo; log in production
            }
        }
    }
}