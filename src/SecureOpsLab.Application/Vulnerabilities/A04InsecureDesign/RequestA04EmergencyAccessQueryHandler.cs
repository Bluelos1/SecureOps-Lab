using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Vulnerabilities;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Application.Vulnerabilities.A04InsecureDesign;

public sealed class RequestA04EmergencyAccessQueryHandler
{
    private const string WorkflowName = "emergency-access";

    private readonly ILabCloudAuditLog _cloudAuditLog;
    private readonly VulnerabilityRuntimeState _vulnerabilityState;

    public RequestA04EmergencyAccessQueryHandler(
        ILabCloudAuditLog cloudAuditLog,
        VulnerabilityRuntimeState vulnerabilityState)
    {
        _cloudAuditLog = cloudAuditLog;
        _vulnerabilityState = vulnerabilityState;
    }

    public async Task<A04EmergencyAccessResponse> Handle(
        RequestA04EmergencyAccessQuery query,
        CancellationToken cancellationToken)
    {
        var occurredAtUtc = DateTime.UtcNow;
        var vulnerable = _vulnerabilityState.A04InsecureDesign;
        var response = vulnerable
            ? BuildVulnerableResponse(query, occurredAtUtc)
            : BuildSafeResponse(query, occurredAtUtc);

        await WriteCloudEventAsync(
            response,
            vulnerable ? "BusinessRuleBypass" : "EmergencyAccessApprovalRequired",
            WorkflowName,
            cancellationToken);

        return response;
    }

    private async Task WriteCloudEventAsync(
        A04EmergencyAccessResponse response,
        string eventType,
        string targetId,
        CancellationToken cancellationToken)
    {
        await _cloudAuditLog.WriteAsync(new LabCloudAuditEvent
        {
            EventType = eventType,
            RuleId = response.Exploited ? "LAB-A04-DESIGN" : "LAB-A04-AUDIT",
            Severity = response.Exploited ? "High" : "Info",
            UserId = response.RequestedByUserId,
            TargetType = "EmergencyAccessWorkflow",
            TargetId = targetId,
            Result = response.Result,
            Details = response.Evidence,
            OccurredAtUtc = response.OccurredAtUtc
        }, cancellationToken);

        response.CloudEventWritten = true;
    }

    private static A04EmergencyAccessResponse BuildVulnerableResponse(
        RequestA04EmergencyAccessQuery query,
        DateTime occurredAtUtc)
    {
        return new A04EmergencyAccessResponse
        {
            ScenarioId = VulnerabilityModuleIds.A04Design,
            OwaspCategory = "A04 Insecure Design",
            VulnerableMode = true,
            Exploited = true,
            Blocked = false,
            CloudEventWritten = false,
            Result = "EmergencyAccessGrantedWithoutApproval",
            Evidence = "The business workflow granted emergency access without an approval step.",
            SafeControl = "Require explicit approval before issuing emergency access.",
            RequestedByUserId = query.CurrentUserId,
            OccurredAtUtc = occurredAtUtc,
            Artifacts = new Dictionary<string, string>
            {
                ["workflow"] = WorkflowName,
                ["approvalRequired"] = "false"
            }
        };
    }

    private static A04EmergencyAccessResponse BuildSafeResponse(
        RequestA04EmergencyAccessQuery query,
        DateTime occurredAtUtc)
    {
        return new A04EmergencyAccessResponse
        {
            ScenarioId = VulnerabilityModuleIds.A04Design,
            OwaspCategory = "A04 Insecure Design",
            VulnerableMode = false,
            Exploited = false,
            Blocked = true,
            CloudEventWritten = false,
            Result = "ApprovalRequired",
            Evidence = "The workflow refused to grant emergency access without approval.",
            SafeControl = "Business rule requires approval before access is granted.",
            RequestedByUserId = query.CurrentUserId,
            OccurredAtUtc = occurredAtUtc,
            Artifacts = new Dictionary<string, string>
            {
                ["workflow"] = WorkflowName,
                ["approvalRequired"] = "true"
            }
        };
    }
}
