using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureOpsLab.Application.Common.CloudLogging;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Persistence;
using SecureOpsLab.Application.Common.Storage;
using SecureOpsLab.Contracts.ObjectStorage;
using SecureOpsLab.Domain.Model.Auditing;
using SecureOpsLab.Domain.Model.Documents;

namespace SecureOpsLab.Application.Vulnerabilities.A05SecurityMisconfiguration;

public sealed class GetA05ObjectByDocumentIdQueryHandler
{
    private readonly ILabDbContext _dbContext;
    private readonly ILabCloudAuditLog _cloudAuditLog;
    private readonly ILabObjectStorage _objectStorage;
    private readonly VulnerabilityRuntimeState _vulnerabilityState;
    private readonly ObjectStorageOptions _objectStorageOptions;
    private readonly ILogger<GetA05ObjectByDocumentIdQueryHandler> _logger;

    public GetA05ObjectByDocumentIdQueryHandler(
        ILabDbContext dbContext,
        ILabCloudAuditLog cloudAuditLog,
        ILabObjectStorage objectStorage,
        VulnerabilityRuntimeState vulnerabilityState,
        IOptions<SecurityLabOptions> options,
        ILogger<GetA05ObjectByDocumentIdQueryHandler> logger)
    {
        _dbContext = dbContext;
        _cloudAuditLog = cloudAuditLog;
        _objectStorage = objectStorage;
        _vulnerabilityState = vulnerabilityState;
        _objectStorageOptions = options.Value.ObjectStorage;
        _logger = logger;
    }

    public async Task<LabObjectDetailsResponse?> Handle(
        GetA05ObjectByDocumentIdQuery query,
        CancellationToken cancellationToken)
    {
        IQueryable<LabDocument> documents = _dbContext.Documents.AsNoTracking()
            .Where(x => x.Id == query.DocumentId);

        if (_vulnerabilityState.A05SecurityMisconfiguration)
        {
            _logger.LogWarning(
                "LAB-A05-S3 vulnerable module active: user {UserId} requested object for document {DocumentId} without owner check",
                query.CurrentUserId,
                query.DocumentId);
        }
        else
        {
            documents = documents.Where(x => x.OwnerId == query.CurrentUserId);
        }

        var document = await documents.FirstOrDefaultAsync(cancellationToken);

        if (document is null)
        {
            var eventTime = DateTime.UtcNow;
            await AddCloudAuditEventAsync(query, null, "ObjectReadDenied", "LAB-A05-AUDIT", "Info", "DeniedOrNotFound", "Object read was denied before S3 access.", eventTime, cancellationToken);
            await AddAuditEventAsync(query, "DeniedOrNotFound", eventTime, cancellationToken);
            return null;
        }

        var objectKey = LabObjectKeys.ForDocument(document.Id);
        var content = await _objectStorage.ReadTextObjectAsync(objectKey, cancellationToken);

        if (content is null)
        {
            var eventTime = DateTime.UtcNow;
            await AddCloudAuditEventAsync(query, document, "ObjectReadMissing", "LAB-A05-AUDIT", "Info", "MissingObject", "S3 object was not found in LocalStack.", eventTime, cancellationToken);
            await AddAuditEventAsync(query, "MissingObject", eventTime, cancellationToken);
            return null;
        }

        var returnedAtUtc = DateTime.UtcNow;
        var isCrossOwnerRead = document.OwnerId != query.CurrentUserId;

        await AddCloudAuditEventAsync(
            query,
            document,
            isCrossOwnerRead ? "CrossOwnerObjectRead" : "ObjectReadReturned",
            isCrossOwnerRead ? "LAB-A05-S3" : "LAB-A05-AUDIT",
            isCrossOwnerRead ? "High" : "Info",
            "Returned",
            isCrossOwnerRead
                ? "A user received a LocalStack S3 object for another user's document."
                : "LocalStack S3 object read event captured for cloud log analysis.",
            returnedAtUtc,
            cancellationToken);

        await AddAuditEventAsync(query, "Returned", returnedAtUtc, cancellationToken);

        return new LabObjectDetailsResponse
        {
            DocumentId = document.Id,
            DocumentTitle = document.Title,
            OwnerId = document.OwnerId,
            RequestedByUserId = query.CurrentUserId,
            BucketName = _objectStorageOptions.BucketName,
            ObjectKey = objectKey,
            Provider = "LocalStack S3",
            Content = content,
            RetrievedAtUtc = returnedAtUtc
        };
    }

    private async Task AddCloudAuditEventAsync(
        GetA05ObjectByDocumentIdQuery query,
        LabDocument? document,
        string eventType,
        string ruleId,
        string severity,
        string result,
        string details,
        DateTime occurredAtUtc,
        CancellationToken cancellationToken)
    {
        await _cloudAuditLog.WriteAsync(new LabCloudAuditEvent
        {
            EventType = eventType,
            RuleId = ruleId,
            Severity = severity,
            UserId = query.CurrentUserId,
            OwnerId = document?.OwnerId,
            TargetType = "LabObject",
            TargetId = LabObjectKeys.ForDocument(query.DocumentId),
            Result = result,
            Details = details,
            OccurredAtUtc = occurredAtUtc
        }, cancellationToken);
    }

    private async Task AddAuditEventAsync(
        GetA05ObjectByDocumentIdQuery query,
        string result,
        DateTime occurredAtUtc,
        CancellationToken cancellationToken)
    {
        _dbContext.AuditEvents.Add(new AuditEvent
        {
            Id = Guid.NewGuid(),
            UserId = query.CurrentUserId,
            Action = "ReadObjectStorageDocument",
            TargetType = "LabObject",
            TargetId = query.DocumentId.ToString(),
            Result = result,
            OccurredAtUtc = occurredAtUtc
        });

        await _dbContext.SaveChangesAsync(cancellationToken);
    }
}
