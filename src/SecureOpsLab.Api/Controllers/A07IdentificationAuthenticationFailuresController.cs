using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Common;
using SecureOpsLab.Application.Vulnerabilities.A07IdentificationAuthenticationFailures;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/vulnerabilities/a07-identification-authentication")]
public sealed class A07IdentificationAuthenticationFailuresController : ControllerBase
{
    private const string LabUserHeaderName = "X-Lab-User-Id";

    private readonly GetA07DefaultLoginQueryHandler _getDefaultLoginQueryHandler;
    private readonly ILogger<A07IdentificationAuthenticationFailuresController> _logger;

    public A07IdentificationAuthenticationFailuresController(
        GetA07DefaultLoginQueryHandler getDefaultLoginQueryHandler,
        ILogger<A07IdentificationAuthenticationFailuresController> logger)
    {
        _getDefaultLoginQueryHandler = getDefaultLoginQueryHandler;
        _logger = logger;
    }

    [HttpGet("default-login")]
    public async Task<ActionResult<A07DefaultLoginResponse>> DefaultLogin(
        [FromQuery] string? password,
        CancellationToken cancellationToken)
    {
        var currentUserId = GetCurrentUserId();
        var input = password ?? string.Empty;

        _logger.LogInformation(
            "Running A07 default login scenario for lab user {UserId}",
            currentUserId);

        var result = await _getDefaultLoginQueryHandler.Handle(
            new GetA07DefaultLoginQuery(currentUserId, input),
            cancellationToken);

        return ToActionResult(result);
    }

    private ActionResult<A07DefaultLoginResponse> ToActionResult(A07DefaultLoginResponse response)
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
