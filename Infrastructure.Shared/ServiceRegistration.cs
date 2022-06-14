using Application.Interfaces;
using Domain.Settings;
using Infrastructure.Shared.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Infrastructure.Shared;

public static class ServiceRegistration
{
    public static void AddSharedInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<MailSettings>(configuration.GetSection("MailSettings"));
        services.AddTransient<IDateTimeService, DateTimeService>();
        services.AddTransient<IEmailService, EmailService>();
    }
}