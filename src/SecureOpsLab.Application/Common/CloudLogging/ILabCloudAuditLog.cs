namespace SecureOpsLab.Application.Common.CloudLogging;

public interface ILabCloudAuditLog
{
    Task WriteAsync(LabCloudAuditEvent auditEvent, CancellationToken cancellationToken);
    Task<IReadOnlyList<LabCloudAuditEvent>> ReadEventsAsync(CancellationToken cancellationToken);
}
