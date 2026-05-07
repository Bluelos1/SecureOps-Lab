using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Persistence;
using SecureOpsLab.Contracts.Documents;
using SecureOpsLab.Domain.Model.Documents;

namespace SecureOpsLab.Application.Vulnerabilities.A01BrokenAccessControl;

public sealed class GetA01DocumentsQueryHandler
{
    private readonly ILabDbContext _dbContext;
    private readonly ILabCloudAuditLog _cloudAuditLog;
    private readonly VulnerabilityRuntimeState _vulnerabilityState;
    private readonly ILogger<GetA01DocumentsQueryHandler> _logger;

    public GetA01DocumentsQueryHandler(
        ILabDbContext dbContext,
        ILabCloudAuditLog cloudAuditLog,
        VulnerabilityRuntimeState vulnerabilityState,
        ILogger<GetA01DocumentsQueryHandler> logger)
    {
        _dbContext = dbContext;
        _cloudAuditLog = cloudAuditLog;
        _vulnerabilityState = vulnerabilityState;
        _logger = logger;
    }

    public async Task<IReadOnlyList<LabDocumentListItemResponse>> Handle(
        GetA01DocumentsQuery query,
        CancellationToken cancellationToken)
    {
        IQueryable<LabDocument> documents = _dbContext.Documents.AsNoTracking();

        if (_vulnerabilityState.A01BrokenAccessControl)
        {
            _logger.LogWarning(
                "LAB-A01-BAC vulnerable module active: document list returned without owner filter for user {UserId}",
                query.CurrentUserId);
        }
        else
        {
            documents = documents.Where(x => x.OwnerId == query.CurrentUserId);
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

        var leakedDocuments = result.Where(x => x.OwnerId != query.CurrentUserId).ToList();

        await _cloudAuditLog.WriteAsync(new LabCloudAuditEvent
        {
            EventType = leakedDocuments.Count > 0 ? "CrossOwnerDocumentList" : "DocumentListReturned",
            RuleId = leakedDocuments.Count > 0 ? "LAB-A01-LIST" : "LAB-A01-AUDIT",
            Severity = leakedDocuments.Count > 0 ? "Medium" : "Info",
            UserId = query.CurrentUserId,
            OwnerId = leakedDocuments.FirstOrDefault()?.OwnerId,
            TargetType = "LabDocument",
            TargetId = "list",
            Result = $"Returned:{result.Count}",
            Details = leakedDocuments.Count > 0
                ? $"Document list included {leakedDocuments.Count} item(s) owned by another lab user."
                : "Document list event captured for cloud log analysis.",
            OccurredAtUtc = DateTime.UtcNow
        }, cancellationToken);

        return result;
    }
}
