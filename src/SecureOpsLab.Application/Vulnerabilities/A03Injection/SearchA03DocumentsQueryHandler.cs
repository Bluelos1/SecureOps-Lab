using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Persistence;
using SecureOpsLab.Contracts.Documents;
using SecureOpsLab.Domain.Model.Auditing;
using SecureOpsLab.Domain.Model.Documents;

namespace SecureOpsLab.Application.Vulnerabilities.A03Injection;

public sealed class SearchA03DocumentsQueryHandler
{
    private readonly ILabDbContext _dbContext;
    private readonly ILabCloudAuditLog _cloudAuditLog;
    private readonly VulnerabilityRuntimeState _vulnerabilityState;
    private readonly ILogger<SearchA03DocumentsQueryHandler> _logger;

    public SearchA03DocumentsQueryHandler(
        ILabDbContext dbContext,
        ILabCloudAuditLog cloudAuditLog,
        VulnerabilityRuntimeState vulnerabilityState,
        ILogger<SearchA03DocumentsQueryHandler> logger)
    {
        _dbContext = dbContext;
        _cloudAuditLog = cloudAuditLog;
        _vulnerabilityState = vulnerabilityState;
        _logger = logger;
    }

    public async Task<IReadOnlyList<LabDocumentListItemResponse>> Handle(
        SearchA03DocumentsQuery query,
        CancellationToken cancellationToken)
    {
        var searchTerm = query.SearchTerm.Trim();
        IQueryable<LabDocument> documents;

        if (_vulnerabilityState.A03Injection)
        {
            _logger.LogWarning(
                "LAB-A03-SQLI vulnerable module active: user {UserId} searched documents with raw term {SearchTerm}",
                query.CurrentUserId,
                searchTerm);

            var vulnerableSql = $"""
                SELECT "Id", "Title", "Content", "Classification", "OwnerId", "CreatedAtUtc"
                FROM lab_documents
                WHERE "OwnerId" = '{query.CurrentUserId}' AND "Title" ILIKE '%{searchTerm}%'
                """;

            documents = _dbContext.Documents.FromSqlRaw(vulnerableSql).AsNoTracking();
        }
        else
        {
            documents = _dbContext.Documents.AsNoTracking()
                .Where(x => x.OwnerId == query.CurrentUserId);

            if (!string.IsNullOrWhiteSpace(searchTerm))
            {
                documents = documents.Where(x => x.Title.Contains(searchTerm));
            }
        }

        var result = await documents
            .OrderByDescending(x => x.CreatedAtUtc)
            .Select(x => new LabDocumentListItemResponse
            {
                Id = x.Id,
                Title = x.Title,
                Classification = x.Classification,
                OwnerId = x.OwnerId,
                CreatedAtUtc = x.CreatedAtUtc
            })
            .ToListAsync(cancellationToken);

        var eventTime = DateTime.UtcNow;
        var leakedDocuments = result.Where(x => x.OwnerId != query.CurrentUserId).ToList();
        var isInjectionPayload = searchTerm.Contains('\'') ||
            searchTerm.Contains("--", StringComparison.Ordinal) ||
            searchTerm.Contains(" or ", StringComparison.OrdinalIgnoreCase);
        var isBypass = isInjectionPayload && leakedDocuments.Count > 0;

        await _cloudAuditLog.WriteAsync(new LabCloudAuditEvent
        {
            EventType = isBypass
                ? "SqlInjectionSearchBypass"
                : isInjectionPayload ? "SqlInjectionSearchBlocked" : "DocumentSearch",
            RuleId = isBypass ? "LAB-A03-SQLI" : "LAB-A03-AUDIT",
            Severity = isBypass ? "High" : "Info",
            UserId = query.CurrentUserId,
            OwnerId = leakedDocuments.FirstOrDefault()?.OwnerId,
            TargetType = "LabDocumentSearch",
            TargetId = searchTerm,
            Result = $"Returned:{result.Count}",
            Details = isBypass
                ? "Injected search term returned document(s) owned by another lab user."
                : "Document search event captured for cloud log analysis.",
            OccurredAtUtc = eventTime
        }, cancellationToken);

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            Id = Guid.NewGuid(),
            UserId = query.CurrentUserId,
            Action = "SearchLabDocuments",
            TargetType = "LabDocument",
            TargetId = searchTerm,
            Result = $"Returned:{result.Count}",
            OccurredAtUtc = eventTime
        });

        await _dbContext.SaveChangesAsync(cancellationToken);

        return result;
    }
}
