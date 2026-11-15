using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Vulnerabilities;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Application.Vulnerabilities.A08SoftwareDataIntegrityFailures;

public sealed class AcceptA08UnsignedUpdateQueryHandler
{
    private const string DefaultPackageUrl = "http://updates.local/unsigned-plugin.zip";

    private readonly ILabCloudAuditLog _cloudAuditLog;
    private readonly VulnerabilityRuntimeState _vulnerabilityState;

    public AcceptA08UnsignedUpdateQueryHandler(
        ILabCloudAuditLog cloudAuditLog,
        VulnerabilityRuntimeState vulnerabilityState)
    {
        _cloudAuditLog = cloudAuditLog;
        _vulnerabilityState = vulnerabilityState;
    }

    public async Task<A08UnsignedUpdateResponse> Handle(
        AcceptA08UnsignedUpdateQuery query,
        CancellationToken cancellationToken)
    {
        var occurredAtUtc = DateTime.UtcNow;
        var packageUrl = string.IsNullOrWhiteSpace(query.PackageUrl) ? DefaultPackageUrl : query.PackageUrl;
        var vulnerable = _vulnerabilityState.A08SoftwareDataIntegrityFailures;
        var response = vulnerable
            ? BuildVulnerableResponse(query.CurrentUserId, packageUrl, occurredAtUtc)
            : BuildSafeResponse(query.CurrentUserId, packageUrl, occurredAtUtc);

        await WriteCloudEventAsync(
            response,
            vulnerable ? "UnsignedUpdateAccepted" : "UnsignedUpdateRejected",
            packageUrl,
            cancellationToken);

        return response;
    }

    private async Task WriteCloudEventAsync(
        A08UnsignedUpdateResponse response,
        string eventType,
        string targetId,
        CancellationToken cancellationToken)
    {
        await _cloudAuditLog.WriteAsync(new LabCloudAuditEvent
        {
            EventType = eventType,
            RuleId = response.Exploited ? "LAB-A08-INTEGRITY" : "LAB-A08-AUDIT",
            Severity = response.Exploited ? "High" : "Info",
            UserId = response.RequestedByUserId,
            TargetType = "UnsignedUpdate",
            TargetId = targetId,
            Result = response.Result,
            Details = response.Evidence,
            OccurredAtUtc = response.OccurredAtUtc
        }, cancellationToken);

        response.CloudEventWritten = true;
    }

    private static A08UnsignedUpdateResponse BuildVulnerableResponse(
        Guid currentUserId,
        string packageUrl,
        DateTime occurredAtUtc)
    {
        return new A08UnsignedUpdateResponse
        {
            ScenarioId = VulnerabilityModuleIds.A08Integrity,
            OwaspCategory = "A08 Software and Data Integrity Failures",
            VulnerableMode = true,
            Exploited = true,
            Blocked = false,
            CloudEventWritten = false,
            Result = "UnsignedUpdateAccepted",
            Evidence = "The update workflow trusted an unsigned plugin package supplied by URL.",
            SafeControl = "Require signed packages and verify integrity before accepting updates.",
            RequestedByUserId = currentUserId,
            OccurredAtUtc = occurredAtUtc,
            Artifacts = new Dictionary<string, string>
            {
                ["packageUrl"] = packageUrl,
                ["signatureVerified"] = "false"
            }
        };
    }

    private static A08UnsignedUpdateResponse BuildSafeResponse(
        Guid currentUserId,
        string packageUrl,
        DateTime occurredAtUtc)
    {
        return new A08UnsignedUpdateResponse
        {
            ScenarioId = VulnerabilityModuleIds.A08Integrity,
            OwaspCategory = "A08 Software and Data Integrity Failures",
            VulnerableMode = false,
            Exploited = false,
            Blocked = true,
            CloudEventWritten = false,
            Result = "UnsignedUpdateRejected",
            Evidence = "The update workflow rejected the package because its signature was not verified.",
            SafeControl = "Unsigned packages are rejected before installation.",
            RequestedByUserId = currentUserId,
            OccurredAtUtc = occurredAtUtc,
            Artifacts = new Dictionary<string, string>
            {
                ["packageUrl"] = packageUrl,
                ["signatureVerified"] = "false"
            }
        };
    }
}
