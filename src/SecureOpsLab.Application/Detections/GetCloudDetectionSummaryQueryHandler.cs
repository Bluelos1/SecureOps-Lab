using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Contracts.Detections;

namespace SecureOpsLab.Application.Detections;

public sealed class GetCloudDetectionSummaryQueryHandler
{
    private static readonly IReadOnlyDictionary<string, string> AlertMessages = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["CrossOwnerDocumentRead"] = "User received a lab document owned by another user.",
        ["CrossOwnerDocumentList"] = "User listed lab documents owned by another user.",
        ["SensitiveSecretDisclosure"] = "Endpoint returned plaintext secret material.",
        ["SqlInjectionSearchBypass"] = "Injected search term returned documents owned by another user.",
        ["BusinessRuleBypass"] = "Business workflow granted access without required approval.",
        ["CrossOwnerObjectRead"] = "User received a LocalStack S3 object for another user's document.",
        ["VulnerableComponentExploit"] = "Simulated legacy component accepted an exploit marker.",
        ["DefaultCredentialLogin"] = "Default lab credential was accepted for authentication.",
        ["UnsignedUpdateAccepted"] = "Unsigned update package was accepted by the update workflow.",
        ["ServerSideRequestForgery"] = "Server fetched an internal or cloud-local endpoint controlled by user input.",
        ["SuspiciousHttpInput"] = "Generic HTTP detector matched suspicious request input."
    };

    private readonly ILabCloudAuditLog _cloudAuditLog;

    public GetCloudDetectionSummaryQueryHandler(ILabCloudAuditLog cloudAuditLog)
    {
        _cloudAuditLog = cloudAuditLog;
    }

    public async Task<CloudDetectionSummaryResponse> Handle(CancellationToken cancellationToken)
    {
        var events = await _cloudAuditLog.ReadEventsAsync(cancellationToken);
        var orderedEvents = events
            .OrderByDescending(x => x.OccurredAtUtc)
            .ToList();
        var alerts = orderedEvents
            .Where(IsAlert)
            .Select(ToAlert)
            .ToList();

        return new CloudDetectionSummaryResponse
        {
            AnalyzedAtUtc = DateTime.UtcNow,
            Source = "LocalStack CloudWatch Logs",
            EventCount = orderedEvents.Count,
            AlertCount = alerts.Count,
            Alerts = alerts,
            Events = orderedEvents.Select(ToEventResponse).ToList()
        };
    }

    private static bool IsAlert(LabCloudAuditEvent auditEvent)
    {
        return AlertMessages.ContainsKey(auditEvent.EventType);
    }

    private static CloudDetectionAlertResponse ToAlert(LabCloudAuditEvent auditEvent)
    {
        return new CloudDetectionAlertResponse
        {
            RuleId = auditEvent.RuleId,
            Severity = auditEvent.Severity,
            Message = BuildMessage(auditEvent),
            EventType = auditEvent.EventType,
            UserId = auditEvent.UserId,
            OwnerId = auditEvent.OwnerId,
            TargetType = auditEvent.TargetType,
            TargetId = auditEvent.TargetId,
            OccurredAtUtc = auditEvent.OccurredAtUtc
        };
    }

    private static string BuildMessage(LabCloudAuditEvent auditEvent)
    {
        return AlertMessages.GetValueOrDefault(auditEvent.EventType, auditEvent.Details);
    }

    private static CloudAuditEventResponse ToEventResponse(LabCloudAuditEvent auditEvent)
    {
        return new CloudAuditEventResponse
        {
            EventType = auditEvent.EventType,
            RuleId = auditEvent.RuleId,
            Severity = auditEvent.Severity,
            UserId = auditEvent.UserId,
            OwnerId = auditEvent.OwnerId,
            TargetType = auditEvent.TargetType,
            TargetId = auditEvent.TargetId,
            Result = auditEvent.Result,
            Details = auditEvent.Details,
            OccurredAtUtc = auditEvent.OccurredAtUtc
        };
    }
}
