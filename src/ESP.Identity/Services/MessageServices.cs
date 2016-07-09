using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Threading.Tasks;

namespace ESP.Identity.Services
{
    // This class is used by the application to send Email and SMS
    // when you turn on two-factor authentication in ASP.NET Identity.
    // For more details see this link http://go.microsoft.com/fwlink/?LinkID=532713
    public class AuthMessageSender : IEmailSender, ISmsSender
    {
        public AuthMessageSenderOptions Options { get; }
        private readonly ILogger _logger;

        public AuthMessageSender(IOptions<AuthMessageSenderOptions> optionsAccessor, ILoggerFactory loggerFactory)
        {
            Options = optionsAccessor.Value;
            _logger = loggerFactory.CreateLogger<AuthMessageSender>();
        }

        /// <summary>
        /// Send an email message
        /// </summary>
        /// <param name="emailAddress">Email address of recipient</param>
        /// <param name="subject">Email subject</param>
        /// <param name="message">Email message</param>
        /// <returns></returns>
        public Task SendEmailAsync(string emailAddress, string subject, string message)
        {
            // Construct email message
            var myMessage = new SendGrid.SendGridMessage();
            myMessage.AddTo(emailAddress);
            myMessage.From = new System.Net.Mail.MailAddress("account@espdevelopment.com", "ESP Account");
            myMessage.Subject = subject;
            myMessage.Text = message;
            myMessage.Html = message;
            var credentials = new System.Net.NetworkCredential(
                Options.SendGridUser,
                Options.SendGridKey);

            // Send the email
            var transportWeb = new SendGrid.Web(credentials);
            if (transportWeb != null)
            {
                try
                {
                    transportWeb.DeliverAsync(myMessage);
                    return Task.FromResult(0);
                }
                catch (Exception e)
                {
                    _logger.LogError(e.Message);
                }
            }
            return Task.FromResult(1);
        }

        public Task SendSmsAsync(string number, string message)
        {
            // Plug in your SMS service here to send a text message.
            return Task.FromResult(0);
        }

    }
}
