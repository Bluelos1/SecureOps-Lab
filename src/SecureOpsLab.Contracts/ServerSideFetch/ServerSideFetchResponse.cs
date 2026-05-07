namespace SecureOpsLab.Contracts.ServerSideFetch;

public sealed class ServerSideFetchResponse
{
    public string TargetUrl { get; init; } = string.Empty;
    public string Host { get; init; } = string.Empty;
    public bool Fetched { get; init; }
    public bool Blocked { get; init; }
    public string BlockReason { get; init; } = string.Empty;
    public int? StatusCode { get; init; }
    public string ContentType { get; init; } = string.Empty;
    public string BodyPreview { get; init; } = string.Empty;
    public Guid RequestedByUserId { get; init; }
    public DateTime CompletedAtUtc { get; init; }
}
