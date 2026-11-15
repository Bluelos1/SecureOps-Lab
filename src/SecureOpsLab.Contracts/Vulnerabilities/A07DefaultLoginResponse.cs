namespace SecureOpsLab.Contracts.Vulnerabilities;

public sealed class A07DefaultLoginResponse
{
    public required string ScenarioId { get; init; }
    public required string OwaspCategory { get; init; }
    public required bool VulnerableMode { get; init; }
    public required bool Exploited { get; init; }
    public required bool Blocked { get; init; }
    public bool CloudEventWritten { get; set; }
    public required string Result { get; init; }
    public required string Evidence { get; init; }
    public required string SafeControl { get; init; }
    public required Guid RequestedByUserId { get; init; }
    public required DateTime OccurredAtUtc { get; init; }
    public IReadOnlyDictionary<string, string> Artifacts { get; init; } = new Dictionary<string, string>();
}
