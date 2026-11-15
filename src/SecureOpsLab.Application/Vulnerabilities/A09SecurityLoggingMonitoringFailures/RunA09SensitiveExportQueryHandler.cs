using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Vulnerabilities;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Application.Vulnerabilities.A09SecurityLoggingMonitoringFailures;

public sealed class RunA09SensitiveExportQueryHandler
{
    private const string SensitiveExportAction = "admin-evidence-export";

    private readonly ILabCloudAuditLog _cloudAuditLog;
    private readonly VulnerabilityRuntimeState _vulnerabilityState;

    public RunA09SensitiveExportQueryHandler(
        ILabCloudAuditLog cloudAuditLog,
        VulnerabilityRuntimeState vulnerabilityState)
    {
        _cloudAuditLog = cloudAuditLog;
        _vulnerabilityState = vulnerabilityState;
    }

    public async Task<A09SensitiveExportResponse> Handle(
        RunA09SensitiveExportQuery query,
        CancellationToken cancellationToken)
    {
        var occurredAtUtc = DateTime.UtcNow;

        if (_vulnerabilityState.A09SecurityLoggingMonitoringFailures)
        {
            return BuildVulnerableResponse(query.CurrentUserId, occurredAtUtc);
        }

        var response = BuildSafeResponse(query.CurrentUserId, occurredAtUtc);
        await WriteCloudEventAsync(response, cancellationToken);

        return response;
    }

    private async Task WriteCloudEventAsync(
        A09SensitiveExportResponse response,
        CancellationToken cancellationToken)
    {
        await _cloudAuditLog.WriteAsync(new LabCloudAuditEvent
        {
            EventType = "SensitiveActionLogged",
            RuleId = "LAB-A09-AUDIT",
            Severity = "Info",
            UserId = response.RequestedByUserId,
            TargetType = "SensitiveExport",
            TargetId = SensitiveExportAction,
            Result = response.Result,
            Details = response.Evidence,
            OccurredAtUtc = response.OccurredAtUtc
        }, cancellationToken);

        response.CloudEventWritten = true;
    }

    private static A09SensitiveExportResponse BuildVulnerableResponse(
        Guid currentUserId,
        DateTime occurredAtUtc)
    {
        return new A09SensitiveExportResponse
        {
            ScenarioId = VulnerabilityModuleIds.A09Logging,
            OwaspCategory = "A09 Security Logging and Monitoring Failures",
            VulnerableMode = true,
            Exploited = true,
            Blocked = false,
            CloudEventWritten = false,
            Result = "SensitiveActionCompletedWithoutCloudAudit",
            Evidence = "The sensitive export completed, but the vulnerable path intentionally did not write a CloudWatch detection event.",
            SafeControl = "Sensitive actions must always produce audit and detection telemetry.",
            RequestedByUserId = currentUserId,
            OccurredAtUtc = occurredAtUtc,
            Artifacts = new Dictionary<string, string>
            {
                ["action"] = SensitiveExportAction,
                ["cloudAuditWritten"] = "false"
            }
        };
    }

    private static A09SensitiveExportResponse BuildSafeResponse(
        Guid currentUserId,
        DateTime occurredAtUtc)
    {
        return new A09SensitiveExportResponse
        {
            ScenarioId = VulnerabilityModuleIds.A09Logging,
            OwaspCategory = "A09 Security Logging and Monitoring Failures",
            VulnerableMode = false,
            Exploited = false,
            Blocked = false,
            CloudEventWritten = false,
            Result = "SensitiveActionLogged",
            Evidence = "The sensitive export completed and produced an audit event for monitoring.",
            SafeControl = "Sensitive actions are logged to CloudWatch Logs.",
            RequestedByUserId = currentUserId,
            OccurredAtUtc = occurredAtUtc,
            Artifacts = new Dictionary<string, string>
            {
                ["action"] = SensitiveExportAction,
                ["cloudAuditWritten"] = "true"
            }
        };
    }
}
