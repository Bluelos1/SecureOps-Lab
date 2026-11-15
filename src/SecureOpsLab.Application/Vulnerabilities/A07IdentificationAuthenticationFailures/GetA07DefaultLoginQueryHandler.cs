using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Vulnerabilities;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Application.Vulnerabilities.A07IdentificationAuthenticationFailures;

public sealed class GetA07DefaultLoginQueryHandler
{
    private const string DefaultPassword = "letmein";
    private const string AccountName = "lab-admin";

    private readonly ILabCloudAuditLog _cloudAuditLog;
    private readonly VulnerabilityRuntimeState _vulnerabilityState;

    public GetA07DefaultLoginQueryHandler(
        ILabCloudAuditLog cloudAuditLog,
        VulnerabilityRuntimeState vulnerabilityState)
    {
        _cloudAuditLog = cloudAuditLog;
        _vulnerabilityState = vulnerabilityState;
    }

    public async Task<A07DefaultLoginResponse> Handle(
        GetA07DefaultLoginQuery query,
        CancellationToken cancellationToken)
    {
        var occurredAtUtc = DateTime.UtcNow;
        var password = string.IsNullOrWhiteSpace(query.Password) ? DefaultPassword : query.Password;
        var vulnerable = _vulnerabilityState.A07IdentificationAuthenticationFailures;
        var exploited = vulnerable && password == DefaultPassword;
        var response = exploited
            ? BuildVulnerableResponse(query.CurrentUserId, occurredAtUtc)
            : BuildRejectedResponse(query.CurrentUserId, vulnerable, occurredAtUtc);

        await WriteCloudEventAsync(
            response,
            exploited ? "DefaultCredentialLogin" : "DefaultCredentialRejected",
            AccountName,
            cancellationToken);

        return response;
    }

    private async Task WriteCloudEventAsync(
        A07DefaultLoginResponse response,
        string eventType,
        string targetId,
        CancellationToken cancellationToken)
    {
        await _cloudAuditLog.WriteAsync(new LabCloudAuditEvent
        {
            EventType = eventType,
            RuleId = response.Exploited ? "LAB-A07-AUTH" : "LAB-A07-AUDIT",
            Severity = response.Exploited ? "High" : "Info",
            UserId = response.RequestedByUserId,
            TargetType = "DefaultLogin",
            TargetId = targetId,
            Result = response.Result,
            Details = response.Evidence,
            OccurredAtUtc = response.OccurredAtUtc
        }, cancellationToken);

        response.CloudEventWritten = true;
    }

    private static A07DefaultLoginResponse BuildVulnerableResponse(
        Guid currentUserId,
        DateTime occurredAtUtc)
    {
        return new A07DefaultLoginResponse
        {
            ScenarioId = VulnerabilityModuleIds.A07Auth,
            OwaspCategory = "A07 Identification and Authentication Failures",
            VulnerableMode = true,
            Exploited = true,
            Blocked = false,
            CloudEventWritten = false,
            Result = "DefaultCredentialAccepted",
            Evidence = "The endpoint accepted a default lab password and issued an admin session.",
            SafeControl = "Disable default credentials and require strong authentication.",
            RequestedByUserId = currentUserId,
            OccurredAtUtc = occurredAtUtc,
            Artifacts = new Dictionary<string, string>
            {
                ["account"] = AccountName,
                ["session"] = "admin-session-issued"
            }
        };
    }

    private static A07DefaultLoginResponse BuildRejectedResponse(
        Guid currentUserId,
        bool vulnerable,
        DateTime occurredAtUtc)
    {
        return new A07DefaultLoginResponse
        {
            ScenarioId = VulnerabilityModuleIds.A07Auth,
            OwaspCategory = "A07 Identification and Authentication Failures",
            VulnerableMode = vulnerable,
            Exploited = false,
            Blocked = true,
            CloudEventWritten = false,
            Result = "AuthenticationRejected",
            Evidence = "Default or invalid credentials were rejected.",
            SafeControl = "Default credentials are disabled.",
            RequestedByUserId = currentUserId,
            OccurredAtUtc = occurredAtUtc,
            Artifacts = new Dictionary<string, string> { ["account"] = AccountName }
        };
    }
}
