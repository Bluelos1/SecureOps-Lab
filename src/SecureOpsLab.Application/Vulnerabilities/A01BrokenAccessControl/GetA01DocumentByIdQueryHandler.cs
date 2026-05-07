using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Persistence;
using SecureOpsLab.Contracts.Documents;
using SecureOpsLab.Domain.Model.Auditing;
using SecureOpsLab.Domain.Model.Documents;

namespace SecureOpsLab.Application.Vulnerabilities.A01BrokenAccessControl;

public sealed class GetA01DocumentByIdQueryHandler
{
    private readonly ILabDbContext _dbContext;
    private readonly ILabCloudAuditLog _cloudAuditLog;
    private readonly VulnerabilityRuntimeState _vulnerabilityState;
    private readonly ILogger<GetA01DocumentByIdQueryHandler> _logger;

    public GetA01DocumentByIdQueryHandler(
        ILabDbContext dbContext,
        ILabCloudAuditLog cloudAuditLog,
        VulnerabilityRuntimeState vulnerabilityState,
        ILogger<GetA01DocumentByIdQueryHandler> logger)
    {
        _dbContext = dbContext;
        _cloudAuditLog = cloudAuditLog;
        _vulnerabilityState = vulnerabilityState;
        _logger = logger;
    }

    public async Task<LabDocumentDetailsResponse?> Handle(
        GetA01DocumentByIdQuery query,
        CancellationToken cancellationToken)
    {
        IQueryable<LabDocument> documents = _dbContext.Documents.AsNoTracking()
            .Where(x => x.Id == query.DocumentId);

        if (_vulnerabilityState.A01BrokenAccessControl)
        {
            _logger.LogWarning(
                "LAB-A01-IDOR vulnerable module active: user {UserId} requested document {DocumentId} without owner check",
                query.CurrentUserId,
                query.DocumentId);
        }
        else
        {
            documents = documents.Where(x => x.OwnerId == query.CurrentUserId);
        }

        var result = await documents
            .Select(x => new LabDocumentDetailsResponse
            {
                Id = x.Id,
                Title = x.Title,
                Content = x.Content,
                Classification = x.Classification,
                OwnerId = x.OwnerId,
                CreatedAtUtc = x.CreatedAtUtc
            })
            .FirstOrDefaultAsync(cancellationToken);

        var eventTime = DateTime.UtcNow;
        var isCrossOwnerRead = result is not null && result.OwnerId != query.CurrentUserId;

        await _cloudAuditLog.WriteAsync(new LabCloudAuditEvent
        {
            EventType = result is null
                ? "DocumentReadDenied"
                : isCrossOwnerRead ? "CrossOwnerDocumentRead" : "DocumentReadReturned",
            RuleId = isCrossOwnerRead ? "LAB-A01-IDOR" : "LAB-A01-AUDIT",
            Severity = isCrossOwnerRead ? "High" : "Info",
            UserId = query.CurrentUserId,
            OwnerId = result?.OwnerId,
            TargetType = "LabDocument",
            TargetId = query.DocumentId.ToString(),
            Result = result is null ? "DeniedOrNotFound" : "Returned",
            Details = isCrossOwnerRead
                ? "A user received a document owned by another lab user."
                : "Document read event captured for cloud log analysis.",
            OccurredAtUtc = eventTime
        }, cancellationToken);

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            Id = Guid.NewGuid(),
            UserId = query.CurrentUserId,
            Action = "ReadLabDocument",
            TargetType = "LabDocument",
            TargetId = query.DocumentId.ToString(),
            Result = result is null ? "DeniedOrNotFound" : "Returned",
            OccurredAtUtc = eventTime
        });

        await _dbContext.SaveChangesAsync(cancellationToken);

        return result;
    }
}
