using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Common;
using SecureOpsLab.Application.Vulnerabilities.A04InsecureDesign;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/vulnerabilities/a04-insecure-design")]
public sealed class A04InsecureDesignController : ControllerBase
{
    private const string LabUserHeaderName = "X-Lab-User-Id";

    private readonly RequestA04EmergencyAccessQueryHandler _requestEmergencyAccessQueryHandler;
    private readonly ILogger<A04InsecureDesignController> _logger;

    public A04InsecureDesignController(
        RequestA04EmergencyAccessQueryHandler requestEmergencyAccessQueryHandler,
        ILogger<A04InsecureDesignController> logger)
    {
        _requestEmergencyAccessQueryHandler = requestEmergencyAccessQueryHandler;
        _logger = logger;
    }

    [HttpGet("emergency-access")]
    public async Task<ActionResult<A04EmergencyAccessResponse>> RequestEmergencyAccess(CancellationToken cancellationToken)
    {
        var currentUserId = GetCurrentUserId();

        _logger.LogInformation(
            "Running A04 emergency access scenario for lab user {UserId}",
            currentUserId);

        var result = await _requestEmergencyAccessQueryHandler.Handle(
            new RequestA04EmergencyAccessQuery(currentUserId),
            cancellationToken);

        return ToActionResult(result);
    }

    private ActionResult<A04EmergencyAccessResponse> ToActionResult(A04EmergencyAccessResponse response)
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
