using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Vulnerabilities;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Application.Vulnerabilities.A02CryptographicFailures;

public sealed class GetA02SecretExportQueryHandler
{
    private const string LegacyBackupTokenName = "legacy-backup-token";
    private const string LeakedTokenValue = "lab-token-2026-plaintext";

    private readonly ILabCloudAuditLog _cloudAuditLog;
    private readonly VulnerabilityRuntimeState _vulnerabilityState;

    public GetA02SecretExportQueryHandler(
        ILabCloudAuditLog cloudAuditLog,
        VulnerabilityRuntimeState vulnerabilityState)
    {
        _cloudAuditLog = cloudAuditLog;
        _vulnerabilityState = vulnerabilityState;
    }

    public async Task<A02SecretExportResponse> Handle(
        GetA02SecretExportQuery query,
        CancellationToken cancellationToken)
    {
        var occurredAtUtc = DateTime.UtcNow;
        var vulnerable = _vulnerabilityState.A02CryptographicFailures;
        var response = vulnerable
            ? BuildVulnerableResponse(query, occurredAtUtc)
            : BuildSafeResponse(query, occurredAtUtc);

        await WriteCloudEventAsync(
            response,
            vulnerable ? "SensitiveSecretDisclosure" : "SecretExportRedacted",
            LegacyBackupTokenName,
            cancellationToken);

        return response;
    }

    private async Task WriteCloudEventAsync(
        A02SecretExportResponse response,
        string eventType,
        string targetId,
        CancellationToken cancellationToken)
    {
        await _cloudAuditLog.WriteAsync(new LabCloudAuditEvent
        {
            EventType = eventType,
            RuleId = response.Exploited ? "LAB-A02-CRYPTO" : "LAB-A02-AUDIT",
            Severity = response.Exploited ? "High" : "Info",
            UserId = response.RequestedByUserId,
            TargetType = "SecretExport",
            TargetId = targetId,
            Result = response.Result,
            Details = response.Evidence,
            OccurredAtUtc = response.OccurredAtUtc
        }, cancellationToken);

        response.CloudEventWritten = true;
    }

    private static A02SecretExportResponse BuildVulnerableResponse(
        GetA02SecretExportQuery query,
        DateTime occurredAtUtc)
    {
        return new A02SecretExportResponse
        {
            ScenarioId = VulnerabilityModuleIds.A02Crypto,
            OwaspCategory = "A02 Cryptographic Failures",
            VulnerableMode = true,
            Exploited = true,
            Blocked = false,
            CloudEventWritten = false,
            Result = "PlaintextSecretReturned",
            Evidence = "The endpoint returned a plaintext backup token that should be encrypted or redacted.",
            SafeControl = "Do not return secret material. Store secrets encrypted and redact responses.",
            RequestedByUserId = query.CurrentUserId,
            OccurredAtUtc = occurredAtUtc,
            Artifacts = new Dictionary<string, string>
            {
                ["secretName"] = LegacyBackupTokenName,
                ["leakedValue"] = LeakedTokenValue
            }
        };
    }

    private static A02SecretExportResponse BuildSafeResponse(
        GetA02SecretExportQuery query,
        DateTime occurredAtUtc)
    {
        return new A02SecretExportResponse
        {
            ScenarioId = VulnerabilityModuleIds.A02Crypto,
            OwaspCategory = "A02 Cryptographic Failures",
            VulnerableMode = false,
            Exploited = false,
            Blocked = true,
            CloudEventWritten = false,
            Result = "SecretRedacted",
            Evidence = "Secret material was redacted before returning the response.",
            SafeControl = "Secret material is never returned in plaintext.",
            RequestedByUserId = query.CurrentUserId,
            OccurredAtUtc = occurredAtUtc,
            Artifacts = new Dictionary<string, string> { ["secretName"] = LegacyBackupTokenName }
        };
    }
}
