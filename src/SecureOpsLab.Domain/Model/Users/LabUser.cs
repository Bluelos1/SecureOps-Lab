using SecureOpsLab.Domain.Model.Documents;

namespace SecureOpsLab.Domain.Model.Users;

public sealed class LabUser
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; }

    public ICollection<LabDocument> Documents { get; set; } = [];
}
