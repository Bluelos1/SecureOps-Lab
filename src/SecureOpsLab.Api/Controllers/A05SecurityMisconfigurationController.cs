using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Common;
using SecureOpsLab.Application.Vulnerabilities.A05SecurityMisconfiguration;
using SecureOpsLab.Contracts.ObjectStorage;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/vulnerabilities/a05-security-misconfiguration/objects")]
public sealed class A05SecurityMisconfigurationController : ControllerBase
{
    private const string LabUserHeaderName = "X-Lab-User-Id";

    private readonly GetA05ObjectByDocumentIdQueryHandler _getObjectByDocumentIdQueryHandler;
    private readonly ILogger<A05SecurityMisconfigurationController> _logger;

    public A05SecurityMisconfigurationController(
        GetA05ObjectByDocumentIdQueryHandler getObjectByDocumentIdQueryHandler,
        ILogger<A05SecurityMisconfigurationController> logger)
    {
        _getObjectByDocumentIdQueryHandler = getObjectByDocumentIdQueryHandler;
        _logger = logger;
    }

    [HttpGet("{documentId:guid}")]
    public async Task<ActionResult<LabObjectDetailsResponse>> GetByDocumentId(
        Guid documentId,
        CancellationToken cancellationToken)
    {
        var currentUserId = GetCurrentUserId();

        _logger.LogInformation(
            "Fetching LocalStack S3 object for document {DocumentId} and lab user {UserId}",
            documentId,
            currentUserId);

        var result = await _getObjectByDocumentIdQueryHandler.Handle(
            new GetA05ObjectByDocumentIdQuery(documentId, currentUserId),
            cancellationToken);

        if (result is null)
        {
            return NotFound();
        }

        return Ok(result);
    }

    private Guid GetCurrentUserId()
    {
        if (Request.Headers.TryGetValue(LabUserHeaderName, out var value) &&
            Guid.TryParse(value, out var parsed))
        {
            return parsed;
        }

        return LabSeedIds.AliceUserId;
    }
}
