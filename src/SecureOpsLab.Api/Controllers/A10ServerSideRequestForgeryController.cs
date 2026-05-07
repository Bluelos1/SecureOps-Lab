using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Common;
using SecureOpsLab.Application.Vulnerabilities.A10ServerSideRequestForgery;
using SecureOpsLab.Contracts.ServerSideFetch;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/vulnerabilities/a10-ssrf")]
public sealed class A10ServerSideRequestForgeryController : ControllerBase
{
    private const string LabUserHeaderName = "X-Lab-User-Id";

    private readonly GetA10ServerSideRequestForgeryQueryHandler _getServerSideRequestForgeryQueryHandler;
    private readonly ILogger<A10ServerSideRequestForgeryController> _logger;

    public A10ServerSideRequestForgeryController(
        GetA10ServerSideRequestForgeryQueryHandler getServerSideRequestForgeryQueryHandler,
        ILogger<A10ServerSideRequestForgeryController> logger)
    {
        _getServerSideRequestForgeryQueryHandler = getServerSideRequestForgeryQueryHandler;
        _logger = logger;
    }

    [HttpGet("fetch")]
    public async Task<ActionResult<ServerSideFetchResponse>> Fetch(
        [FromQuery] string? url,
        CancellationToken cancellationToken)
    {
        var targetUrl = url ?? string.Empty;
        var currentUserId = GetCurrentUserId();

        _logger.LogInformation(
            "Running server-side fetch for target {TargetUrl} and lab user {UserId}",
            targetUrl,
            currentUserId);

        var result = await _getServerSideRequestForgeryQueryHandler.Handle(
            new GetA10ServerSideRequestForgeryQuery(targetUrl, currentUserId),
            cancellationToken);

        if (result.Blocked)
        {
            return StatusCode(StatusCodes.Status403Forbidden, result);
        }

        if (!result.Fetched)
        {
            return StatusCode(StatusCodes.Status502BadGateway, result);
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
