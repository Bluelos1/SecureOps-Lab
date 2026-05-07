using Microsoft.EntityFrameworkCore;
using SecureOpsLab.Domain.Model.Auditing;
using SecureOpsLab.Domain.Model.Documents;
using SecureOpsLab.Domain.Model.Users;

namespace SecureOpsLab.Application.Common.Persistence;

public interface ILabDbContext
{
    DbSet<LabUser> Users { get; }
    DbSet<LabDocument> Documents { get; }
    DbSet<AuditEvent> AuditEvents { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken);
}
