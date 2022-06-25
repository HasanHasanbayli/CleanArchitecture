using Application.DTOs.Email;
using Application.Exceptions;
using Application.Interfaces;
using Domain.Settings;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Infrastructure.Shared.Services;

public class EmailService : IEmailService
{
    private readonly MailSettings _mailSettings;

    public EmailService(IOptions<MailSettings> mailSettings)
    {
        _mailSettings = mailSettings.Value;
    }

    public async Task SendAsync(EmailRequest request)
    {
        try
        {
            // create message
            var email = new MimeMessage();

            email.Sender = new MailboxAddress(_mailSettings.DisplayName,
                request.From ?? _mailSettings.EmailFrom);

            email.To.Add(MailboxAddress.Parse(request.To));

            email.Subject = request.Subject;

            var builder = new BodyBuilder
            {
                HtmlBody = request.Body
            };

            email.Body = builder.ToMessageBody();

            using var smtp = new SmtpClient();

            await smtp.ConnectAsync(_mailSettings.SmtpHost, _mailSettings.SmtpPort, SecureSocketOptions.StartTls);

            await smtp.AuthenticateAsync(_mailSettings.SmtpUser, _mailSettings.SmtpPass);

            await smtp.SendAsync(email);

            await smtp.DisconnectAsync(true);
        }
        catch (Exception ex)
        {
            throw new ApiException(ex.Message);
        }
    }
}