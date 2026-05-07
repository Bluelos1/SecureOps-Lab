namespace SecureOpsLab.Application.Common.CloudLogging;

public sealed class LabCloudAuditEvent
{
    public string EventType { get; init; } = string.Empty;
    public string RuleId { get; init; } = string.Empty;
    public string Severity { get; init; } = "Info";
    public Guid? UserId { get; init; }
    public Guid? OwnerId { get; init; }
    public string TargetType { get; init; } = string.Empty;
    public string TargetId { get; init; } = string.Empty;
    public string Result { get; init; } = string.Empty;
    public string Details { get; init; } = string.Empty;
    public DateTime OccurredAtUtc { get; init; }
}
