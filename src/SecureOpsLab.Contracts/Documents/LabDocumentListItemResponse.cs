namespace SecureOpsLab.Contracts.Documents;

public sealed class LabDocumentListItemResponse
{
    public Guid Id { get; init; }
    public string Title { get; init; } = string.Empty;
    public string Classification { get; init; } = string.Empty;
    public Guid OwnerId { get; init; }
    public DateTime CreatedAtUtc { get; init; }
}
