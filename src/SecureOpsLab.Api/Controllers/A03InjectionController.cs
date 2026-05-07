using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Common;
using SecureOpsLab.Application.Vulnerabilities.A03Injection;
using SecureOpsLab.Contracts.Documents;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/vulnerabilities/a03-injection/documents")]
public sealed class A03InjectionController : ControllerBase
{
    private const string LabUserHeaderName = "X-Lab-User-Id";

    private readonly SearchA03DocumentsQueryHandler _searchDocumentsQueryHandler;
    private readonly ILogger<A03InjectionController> _logger;

    public A03InjectionController(
        SearchA03DocumentsQueryHandler searchDocumentsQueryHandler,
        ILogger<A03InjectionController> logger)
    {
        _searchDocumentsQueryHandler = searchDocumentsQueryHandler;
        _logger = logger;
    }

    [HttpGet("search")]
    public async Task<ActionResult<IReadOnlyList<LabDocumentListItemResponse>>> Search(
        [FromQuery] string? term,
        CancellationToken cancellationToken)
    {
        var currentUserId = GetCurrentUserId();
        var searchTerm = term ?? string.Empty;

        _logger.LogInformation(
            "Searching lab documents for lab user {UserId} with term {SearchTerm}",
            currentUserId,
            searchTerm);

        var result = await _searchDocumentsQueryHandler.Handle(
            new SearchA03DocumentsQuery(searchTerm, currentUserId),
            cancellationToken);

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
