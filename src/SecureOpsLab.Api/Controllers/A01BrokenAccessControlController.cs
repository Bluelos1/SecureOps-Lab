using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Common;
using SecureOpsLab.Application.Vulnerabilities.A01BrokenAccessControl;
using SecureOpsLab.Contracts.Documents;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/vulnerabilities/a01-broken-access-control/documents")]
public sealed class A01BrokenAccessControlController : ControllerBase
{
    private const string LabUserHeaderName = "X-Lab-User-Id";

    private readonly GetA01DocumentsQueryHandler _getDocumentsQueryHandler;
    private readonly GetA01DocumentByIdQueryHandler _getDocumentByIdQueryHandler;
    private readonly ILogger<A01BrokenAccessControlController> _logger;

    public A01BrokenAccessControlController(
        GetA01DocumentsQueryHandler getDocumentsQueryHandler,
        GetA01DocumentByIdQueryHandler getDocumentByIdQueryHandler,
        ILogger<A01BrokenAccessControlController> logger)
    {
        _getDocumentsQueryHandler = getDocumentsQueryHandler;
        _getDocumentByIdQueryHandler = getDocumentByIdQueryHandler;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<LabDocumentListItemResponse>>> GetAll(CancellationToken cancellationToken)
    {
        var currentUserId = GetCurrentUserId();

        _logger.LogInformation("Fetching lab documents list for lab user {UserId}", currentUserId);

        var result = await _getDocumentsQueryHandler.Handle(
            new GetA01DocumentsQuery(currentUserId),
            cancellationToken);

        return Ok(result);
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<LabDocumentDetailsResponse>> GetById(Guid id, CancellationToken cancellationToken)
    {
        var currentUserId = GetCurrentUserId();

        _logger.LogInformation(
            "Fetching lab document {DocumentId} for lab user {UserId}",
            id,
            currentUserId);

        var result = await _getDocumentByIdQueryHandler.Handle(
            new GetA01DocumentByIdQuery(id, currentUserId),
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
