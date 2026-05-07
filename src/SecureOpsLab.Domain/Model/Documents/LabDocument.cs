using SecureOpsLab.Domain.Model.Users;

namespace SecureOpsLab.Domain.Model.Documents;

public sealed class LabDocument
{
    public Guid Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public string Classification { get; set; } = string.Empty;
    public Guid OwnerId { get; set; }
    public LabUser? Owner { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
