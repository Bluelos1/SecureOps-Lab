using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureOpsLab.Application.Common;
using SecureOpsLab.Domain.Model.Documents;
using SecureOpsLab.Domain.Model.Users;

namespace SecureOpsLab.Infrastructure.Persistence;

public static class DatabaseSeeder
{
    public static async Task SeedLabDatabaseAsync(this IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<LabDbContext>();

        await dbContext.Database.EnsureCreatedAsync();
        await EnsureLabTablesAsync(dbContext);

        if (await dbContext.Users.AnyAsync())
        {
            return;
        }

        var now = DateTime.UtcNow;

        dbContext.Users.AddRange(
            new LabUser
            {
                Id = LabSeedIds.AliceUserId,
                Email = "alice@secureops.lab",
                Role = "User",
                CreatedAtUtc = now
            },
            new LabUser
            {
                Id = LabSeedIds.BobUserId,
                Email = "bob@secureops.lab",
                Role = "User",
                CreatedAtUtc = now
            });

        dbContext.Documents.AddRange(
            new LabDocument
            {
                Id = LabSeedIds.AliceDocumentId,
                OwnerId = LabSeedIds.AliceUserId,
                Title = "Alice private document",
                Content = "This document belongs to Alice and is safe to return when Alice is the current lab user.",
                Classification = "Internal",
                CreatedAtUtc = now.AddMinutes(-20)
            },
            new LabDocument
            {
                Id = LabSeedIds.BobDocumentId,
                OwnerId = LabSeedIds.BobUserId,
                Title = "Bob confidential document",
                Content = "This document belongs to Bob. Alice should not be able to read it when access control is enforced.",
                Classification = "Confidential",
                CreatedAtUtc = now.AddMinutes(-10)
            });

        await dbContext.SaveChangesAsync();
    }

    private static async Task EnsureLabTablesAsync(LabDbContext dbContext)
    {
        await dbContext.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS lab_users (
                "Id" uuid PRIMARY KEY,
                "Email" character varying(256) NOT NULL,
                "Role" character varying(50) NOT NULL,
                "CreatedAtUtc" timestamp with time zone NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS "IX_lab_users_Email"
                ON lab_users ("Email");

            CREATE TABLE IF NOT EXISTS lab_documents (
                "Id" uuid PRIMARY KEY,
                "Title" character varying(200) NOT NULL,
                "Content" character varying(4000) NOT NULL,
                "Classification" character varying(50) NOT NULL,
                "OwnerId" uuid NOT NULL REFERENCES lab_users ("Id") ON DELETE RESTRICT,
                "CreatedAtUtc" timestamp with time zone NOT NULL
            );

            CREATE INDEX IF NOT EXISTS "IX_lab_documents_OwnerId"
                ON lab_documents ("OwnerId");

            CREATE TABLE IF NOT EXISTS audit_events (
                "Id" uuid PRIMARY KEY,
                "UserId" uuid NULL,
                "Action" character varying(100) NOT NULL,
                "TargetType" character varying(100) NOT NULL,
                "TargetId" character varying(100) NULL,
                "Result" character varying(50) NOT NULL,
                "OccurredAtUtc" timestamp with time zone NOT NULL
            );
            """);
    }
}
