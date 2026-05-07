namespace SecureOpsLab.Contracts.ObjectStorage;

public sealed class LabObjectDetailsResponse
{
    public Guid DocumentId { get; init; }
    public string DocumentTitle { get; init; } = string.Empty;
    public Guid OwnerId { get; init; }
    public Guid RequestedByUserId { get; init; }
    public string BucketName { get; init; } = string.Empty;
    public string ObjectKey { get; init; } = string.Empty;
    public string Provider { get; init; } = string.Empty;
    public string Content { get; init; } = string.Empty;
    public DateTime RetrievedAtUtc { get; init; }
}
