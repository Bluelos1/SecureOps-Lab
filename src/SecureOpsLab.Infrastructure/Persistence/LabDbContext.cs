using Microsoft.EntityFrameworkCore;
using SecureOpsLab.Application.Common.Persistence;
using SecureOpsLab.Domain.Model.Auditing;
using SecureOpsLab.Domain.Model.Documents;
using SecureOpsLab.Domain.Model.Users;

namespace SecureOpsLab.Infrastructure.Persistence;

public sealed class LabDbContext : DbContext, ILabDbContext
{
    public LabDbContext(DbContextOptions<LabDbContext> options) : base(options)
    {
    }

    public DbSet<LabUser> Users => Set<LabUser>();
    public DbSet<LabDocument> Documents => Set<LabDocument>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<LabUser>(entity =>
        {
            entity.ToTable("lab_users");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Email).IsRequired().HasMaxLength(256);
            entity.Property(x => x.Role).IsRequired().HasMaxLength(50);
            entity.HasIndex(x => x.Email).IsUnique();
        });

        modelBuilder.Entity<LabDocument>(entity =>
        {
            entity.ToTable("lab_documents");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Title).IsRequired().HasMaxLength(200);
            entity.Property(x => x.Content).IsRequired().HasMaxLength(4000);
            entity.Property(x => x.Classification).IsRequired().HasMaxLength(50);
            entity.HasOne(x => x.Owner)
                .WithMany(x => x.Documents)
                .HasForeignKey(x => x.OwnerId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<AuditEvent>(entity =>
        {
            entity.ToTable("audit_events");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Action).IsRequired().HasMaxLength(100);
            entity.Property(x => x.TargetType).IsRequired().HasMaxLength(100);
            entity.Property(x => x.TargetId).HasMaxLength(100);
            entity.Property(x => x.Result).IsRequired().HasMaxLength(50);
        });
    }
}
