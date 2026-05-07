using System.Net;
using Microsoft.Extensions.Logging;
using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Network;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Contracts.ServerSideFetch;

namespace SecureOpsLab.Application.Vulnerabilities.A10ServerSideRequestForgery;

public sealed class GetA10ServerSideRequestForgeryQueryHandler
{
    private readonly ILabCloudAuditLog _cloudAuditLog;
    private readonly ILabHttpFetcher _httpFetcher;
    private readonly VulnerabilityRuntimeState _vulnerabilityState;
    private readonly ILogger<GetA10ServerSideRequestForgeryQueryHandler> _logger;

    public GetA10ServerSideRequestForgeryQueryHandler(
        ILabCloudAuditLog cloudAuditLog,
        ILabHttpFetcher httpFetcher,
        VulnerabilityRuntimeState vulnerabilityState,
        ILogger<GetA10ServerSideRequestForgeryQueryHandler> logger)
    {
        _cloudAuditLog = cloudAuditLog;
        _httpFetcher = httpFetcher;
        _vulnerabilityState = vulnerabilityState;
        _logger = logger;
    }

    public async Task<ServerSideFetchResponse> Handle(
        GetA10ServerSideRequestForgeryQuery query,
        CancellationToken cancellationToken)
    {
        var completedAtUtc = DateTime.UtcNow;

        if (!Uri.TryCreate(query.TargetUrl, UriKind.Absolute, out var uri))
        {
            return await BuildBlockedResponseAsync(
                query,
                string.Empty,
                "The target URL is not a valid absolute URI.",
                completedAtUtc,
                cancellationToken);
        }

        var blockReason = GetBlockReason(uri);

        if (!_vulnerabilityState.A10ServerSideRequestForgery && blockReason is not null)
        {
            return await BuildBlockedResponseAsync(
                query,
                uri.Host,
                blockReason,
                completedAtUtc,
                cancellationToken);
        }

        try
        {
            var result = await _httpFetcher.FetchAsync(uri, cancellationToken);
            var isInternalFetch = blockReason is not null;
            var isSsrf = _vulnerabilityState.A10ServerSideRequestForgery && isInternalFetch;

            await WriteCloudEventAsync(
                query,
                uri,
                isSsrf ? "ServerSideRequestForgery" : "ServerSideFetchReturned",
                isSsrf ? "LAB-A10-SSRF" : "LAB-A10-AUDIT",
                isSsrf ? "High" : "Info",
                $"Fetched:{result.StatusCode}",
                isSsrf
                    ? "Server fetched an internal or cloud-local endpoint controlled by user input."
                    : "Server-side URL fetch event captured for cloud log analysis.",
                DateTime.UtcNow,
                cancellationToken);

            return new ServerSideFetchResponse
            {
                TargetUrl = query.TargetUrl,
                Host = uri.Host,
                Fetched = true,
                Blocked = false,
                StatusCode = result.StatusCode,
                ContentType = result.ContentType,
                BodyPreview = result.BodyPreview,
                RequestedByUserId = query.CurrentUserId,
                CompletedAtUtc = DateTime.UtcNow
            };
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Server-side fetch failed for target {TargetUrl}", query.TargetUrl);

            await WriteCloudEventAsync(
                query,
                uri,
                "ServerSideFetchFailed",
                "LAB-A10-AUDIT",
                "Info",
                "Failed",
                exception.Message,
                DateTime.UtcNow,
                cancellationToken);

            return new ServerSideFetchResponse
            {
                TargetUrl = query.TargetUrl,
                Host = uri.Host,
                Fetched = false,
                Blocked = false,
                BlockReason = exception.Message,
                RequestedByUserId = query.CurrentUserId,
                CompletedAtUtc = DateTime.UtcNow
            };
        }
    }

    private async Task<ServerSideFetchResponse> BuildBlockedResponseAsync(
        GetA10ServerSideRequestForgeryQuery query,
        string host,
        string reason,
        DateTime completedAtUtc,
        CancellationToken cancellationToken)
    {
        await _cloudAuditLog.WriteAsync(new LabCloudAuditEvent
        {
            EventType = "ServerSideFetchBlocked",
            RuleId = "LAB-A10-AUDIT",
            Severity = "Info",
            UserId = query.CurrentUserId,
            TargetType = "ServerSideFetch",
            TargetId = query.TargetUrl,
            Result = "Blocked",
            Details = reason,
            OccurredAtUtc = completedAtUtc
        }, cancellationToken);

        return new ServerSideFetchResponse
        {
            TargetUrl = query.TargetUrl,
            Host = host,
            Fetched = false,
            Blocked = true,
            BlockReason = reason,
            RequestedByUserId = query.CurrentUserId,
            CompletedAtUtc = completedAtUtc
        };
    }

    private async Task WriteCloudEventAsync(
        GetA10ServerSideRequestForgeryQuery query,
        Uri uri,
        string eventType,
        string ruleId,
        string severity,
        string result,
        string details,
        DateTime occurredAtUtc,
        CancellationToken cancellationToken)
    {
        await _cloudAuditLog.WriteAsync(new LabCloudAuditEvent
        {
            EventType = eventType,
            RuleId = ruleId,
            Severity = severity,
            UserId = query.CurrentUserId,
            TargetType = "ServerSideFetch",
            TargetId = uri.ToString(),
            Result = result,
            Details = details,
            OccurredAtUtc = occurredAtUtc
        }, cancellationToken);
    }

    private static string? GetBlockReason(Uri uri)
    {
        if (uri.Scheme is not ("http" or "https"))
        {
            return "Only HTTP and HTTPS URLs are allowed.";
        }

        var host = uri.Host.ToLowerInvariant();

        if (host is "localhost" or "localstack" || host.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
        {
            return "Internal hostnames are blocked in safe mode.";
        }

        if (IPAddress.TryParse(host, out var address) && IsInternalAddress(address))
        {
            return "Internal IP ranges are blocked in safe mode.";
        }

        return null;
    }

    private static bool IsInternalAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        var bytes = address.GetAddressBytes();

        return address.AddressFamily switch
        {
            System.Net.Sockets.AddressFamily.InterNetwork =>
                bytes[0] == 10 ||
                bytes[0] == 127 ||
                bytes[0] == 169 && bytes[1] == 254 ||
                bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
                bytes[0] == 192 && bytes[1] == 168,
            System.Net.Sockets.AddressFamily.InterNetworkV6 =>
                address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.Equals(IPAddress.IPv6Loopback),
            _ => false
        };
    }
}
