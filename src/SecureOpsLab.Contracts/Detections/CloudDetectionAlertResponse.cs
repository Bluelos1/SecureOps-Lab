namespace SecureOpsLab.Contracts.Detections;

public sealed class CloudDetectionAlertResponse
{
    public string RuleId { get; init; } = string.Empty;
    public string Severity { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
    public string EventType { get; init; } = string.Empty;
    public Guid? UserId { get; init; }
    public Guid? OwnerId { get; init; }
    public string TargetType { get; init; } = string.Empty;
    public string TargetId { get; init; } = string.Empty;
    public DateTime OccurredAtUtc { get; init; }
}
