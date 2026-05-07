using System.Text.Json;
using Amazon.CloudWatchLogs;
using Amazon.CloudWatchLogs.Model;
using Microsoft.Extensions.Options;
using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Options;

namespace SecureOpsLab.Infrastructure.CloudLogging;

public sealed class CloudWatchLabAuditLog : ILabCloudAuditLog
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly IAmazonCloudWatchLogs _logsClient;
    private readonly CloudLoggingOptions _options;

    public CloudWatchLabAuditLog(
        IAmazonCloudWatchLogs logsClient,
        IOptions<SecurityLabOptions> options)
    {
        _logsClient = logsClient;
        _options = options.Value.CloudLogging;
    }

    public async Task WriteAsync(LabCloudAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken);

        try
        {
            var sequenceToken = await GetSequenceTokenAsync(cancellationToken);
            var request = new PutLogEventsRequest
            {
                LogGroupName = _options.LogGroupName,
                LogStreamName = _options.LogStreamName,
                LogEvents =
                [
                    new InputLogEvent
                    {
                        Message = JsonSerializer.Serialize(auditEvent, JsonOptions),
                        Timestamp = auditEvent.OccurredAtUtc
                    }
                ],
                SequenceToken = sequenceToken
            };

            await _logsClient.PutLogEventsAsync(request, cancellationToken);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<IReadOnlyList<LabCloudAuditEvent>> ReadEventsAsync(CancellationToken cancellationToken)
    {
        var result = new List<LabCloudAuditEvent>();
        string? nextToken = null;

        do
        {
            var response = await _logsClient.FilterLogEventsAsync(new FilterLogEventsRequest
            {
                LogGroupName = _options.LogGroupName,
                LogStreamNames = [_options.LogStreamName],
                NextToken = nextToken,
                Limit = 100
            }, cancellationToken);

            foreach (var cloudEvent in response.Events)
            {
                if (string.IsNullOrWhiteSpace(cloudEvent.Message))
                {
                    continue;
                }

                var parsed = JsonSerializer.Deserialize<LabCloudAuditEvent>(cloudEvent.Message, JsonOptions);

                if (parsed is not null)
                {
                    result.Add(parsed);
                }
            }

            nextToken = response.NextToken;
        }
        while (!string.IsNullOrWhiteSpace(nextToken));

        return result;
    }

    private async Task<string?> GetSequenceTokenAsync(CancellationToken cancellationToken)
    {
        var response = await _logsClient.DescribeLogStreamsAsync(new DescribeLogStreamsRequest
        {
            LogGroupName = _options.LogGroupName,
            LogStreamNamePrefix = _options.LogStreamName
        }, cancellationToken);

        return response.LogStreams
            .FirstOrDefault(x => x.LogStreamName == _options.LogStreamName)
            ?.UploadSequenceToken;
    }
}
