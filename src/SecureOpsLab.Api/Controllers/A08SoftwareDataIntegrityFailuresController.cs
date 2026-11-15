using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Common;
using SecureOpsLab.Application.Vulnerabilities.A08SoftwareDataIntegrityFailures;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/vulnerabilities/a08-software-data-integrity")]
public sealed class A08SoftwareDataIntegrityFailuresController : ControllerBase
{
    private const string LabUserHeaderName = "X-Lab-User-Id";

    private readonly AcceptA08UnsignedUpdateQueryHandler _acceptUnsignedUpdateQueryHandler;
    private readonly ILogger<A08SoftwareDataIntegrityFailuresController> _logger;

    public A08SoftwareDataIntegrityFailuresController(
        AcceptA08UnsignedUpdateQueryHandler acceptUnsignedUpdateQueryHandler,
        ILogger<A08SoftwareDataIntegrityFailuresController> logger)
    {
        _acceptUnsignedUpdateQueryHandler = acceptUnsignedUpdateQueryHandler;
        _logger = logger;
    }

    [HttpGet("update")]
    public async Task<ActionResult<A08UnsignedUpdateResponse>> AcceptUnsignedUpdate(
        [FromQuery] string? packageUrl,
        CancellationToken cancellationToken)
    {
        var currentUserId = GetCurrentUserId();
        var input = packageUrl ?? string.Empty;

        _logger.LogInformation(
            "Running A08 unsigned update scenario for lab user {UserId}",
            currentUserId);

        var result = await _acceptUnsignedUpdateQueryHandler.Handle(
            new AcceptA08UnsignedUpdateQuery(currentUserId, input),
            cancellationToken);

        return ToActionResult(result);
    }

    private ActionResult<A08UnsignedUpdateResponse> ToActionResult(A08UnsignedUpdateResponse response)
    {
        return response.Blocked ? StatusCode(StatusCodes.Status403Forbidden, response) : Ok(response);
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
