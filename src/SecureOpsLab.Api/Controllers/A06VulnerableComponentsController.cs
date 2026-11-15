using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Common;
using SecureOpsLab.Application.Vulnerabilities.A06VulnerableComponents;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/vulnerabilities/a06-vulnerable-components")]
public sealed class A06VulnerableComponentsController : ControllerBase
{
    private const string LabUserHeaderName = "X-Lab-User-Id";

    private readonly RenderA06LegacyComponentQueryHandler _renderLegacyComponentQueryHandler;
    private readonly ILogger<A06VulnerableComponentsController> _logger;

    public A06VulnerableComponentsController(
        RenderA06LegacyComponentQueryHandler renderLegacyComponentQueryHandler,
        ILogger<A06VulnerableComponentsController> logger)
    {
        _renderLegacyComponentQueryHandler = renderLegacyComponentQueryHandler;
        _logger = logger;
    }

    [HttpGet("render")]
    public async Task<ActionResult<A06LegacyComponentRenderResponse>> RenderWithLegacyComponent(
        [FromQuery] string? payload,
        CancellationToken cancellationToken)
    {
        var currentUserId = GetCurrentUserId();
        var input = payload ?? string.Empty;

        _logger.LogInformation(
            "Running A06 legacy component scenario for lab user {UserId}",
            currentUserId);

        var result = await _renderLegacyComponentQueryHandler.Handle(
            new RenderA06LegacyComponentQuery(currentUserId, input),
            cancellationToken);

        return ToActionResult(result);
    }

    private ActionResult<A06LegacyComponentRenderResponse> ToActionResult(A06LegacyComponentRenderResponse response)
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
