using Amazon.CloudWatchLogs;
using Amazon.CloudWatchLogs.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureOpsLab.Application.Common.Options;

namespace SecureOpsLab.Infrastructure.CloudLogging;

public static class CloudLoggingSeeder
{
    public static async Task SeedLabCloudLoggingAsync(this IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var logsClient = scope.ServiceProvider.GetRequiredService<IAmazonCloudWatchLogs>();
        var options = scope.ServiceProvider.GetRequiredService<IOptions<SecurityLabOptions>>().Value.CloudLogging;
        var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>()
            .CreateLogger("SecureOpsLab.Infrastructure.CloudLogging.CloudLoggingSeeder");

        for (var attempt = 1; attempt <= 12; attempt++)
        {
            try
            {
                await EnsureLogGroupAndStreamAsync(logsClient, options, CancellationToken.None);
                logger.LogInformation(
                    "Seeded LocalStack CloudWatch Logs group {LogGroupName} and stream {LogStreamName}",
                    options.LogGroupName,
                    options.LogStreamName);
                return;
            }
            catch (AmazonCloudWatchLogsException) when (attempt < 12)
            {
                logger.LogWarning(
                    "LocalStack CloudWatch Logs is not ready yet. Retrying cloud logging seed, attempt {Attempt}/12",
                    attempt);
                await Task.Delay(TimeSpan.FromSeconds(2));
            }
        }

        await EnsureLogGroupAndStreamAsync(logsClient, options, CancellationToken.None);
    }

    private static async Task EnsureLogGroupAndStreamAsync(
        IAmazonCloudWatchLogs logsClient,
        CloudLoggingOptions options,
        CancellationToken cancellationToken)
    {
        try
        {
            await logsClient.CreateLogGroupAsync(new CreateLogGroupRequest
            {
                LogGroupName = options.LogGroupName
            }, cancellationToken);
        }
        catch (ResourceAlreadyExistsException)
        {
        }

        try
        {
            await logsClient.CreateLogStreamAsync(new CreateLogStreamRequest
            {
                LogGroupName = options.LogGroupName,
                LogStreamName = options.LogStreamName
            }, cancellationToken);
        }
        catch (ResourceAlreadyExistsException)
        {
        }
    }
}
