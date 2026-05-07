namespace SecureOpsLab.Domain.Model.Auditing;

public sealed class AuditEvent
{
    public Guid Id { get; set; }
    public Guid? UserId { get; set; }
    public string Action { get; set; } = string.Empty;
    public string TargetType { get; set; } = string.Empty;
    public string? TargetId { get; set; }
    public string Result { get; set; } = string.Empty;
    public DateTime OccurredAtUtc { get; set; }
}
