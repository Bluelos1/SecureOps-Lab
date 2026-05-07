namespace SecureOpsLab.Contracts.Detections;

public sealed class CloudDetectionSummaryResponse
{
    public DateTime AnalyzedAtUtc { get; init; }
    public string Source { get; init; } = string.Empty;
    public int EventCount { get; init; }
    public int AlertCount { get; init; }
    public IReadOnlyList<CloudDetectionAlertResponse> Alerts { get; init; } = [];
    public IReadOnlyList<CloudAuditEventResponse> Events { get; init; } = [];
}
