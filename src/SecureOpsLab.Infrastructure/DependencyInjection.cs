using Amazon.CloudWatchLogs;
using Amazon.Runtime;
using Amazon.S3;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Network;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Persistence;
using SecureOpsLab.Application.Common.Storage;
using SecureOpsLab.Infrastructure.CloudLogging;
using SecureOpsLab.Infrastructure.Network;
using SecureOpsLab.Infrastructure.Persistence;
using SecureOpsLab.Infrastructure.Storage;

namespace SecureOpsLab.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddDbContext<LabDbContext>(options =>
            options.UseNpgsql(configuration.GetConnectionString("Postgres")));

        services.AddScoped<ILabDbContext>(provider =>
            provider.GetRequiredService<LabDbContext>());

        services.AddSingleton<IAmazonS3>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<SecurityLabOptions>>().Value.ObjectStorage;
            var config = new AmazonS3Config
            {
                ServiceURL = options.ServiceUrl,
                AuthenticationRegion = options.Region,
                ForcePathStyle = true
            };

            var credentials = new BasicAWSCredentials(options.AccessKey, options.SecretKey);
            return new AmazonS3Client(credentials, config);
        });

        services.AddSingleton<IAmazonCloudWatchLogs>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<SecurityLabOptions>>().Value.CloudLogging;
            var config = new AmazonCloudWatchLogsConfig
            {
                ServiceURL = options.ServiceUrl,
                AuthenticationRegion = options.Region
            };

            var credentials = new BasicAWSCredentials(options.AccessKey, options.SecretKey);
            return new AmazonCloudWatchLogsClient(credentials, config);
        });

        services.AddSingleton<ILabCloudAuditLog, CloudWatchLabAuditLog>();
        services.AddScoped<ILabObjectStorage, S3LabObjectStorage>();
        services.AddSingleton<ILabHttpFetcher>(_ =>
            new HttpClientLabHttpFetcher(new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(5)
            }));

        return services;
    }
}
