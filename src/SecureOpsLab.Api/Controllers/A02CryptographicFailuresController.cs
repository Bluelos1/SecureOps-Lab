using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Common;
using SecureOpsLab.Application.Vulnerabilities.A02CryptographicFailures;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/vulnerabilities/a02-cryptographic-failures")]
public sealed class A02CryptographicFailuresController : ControllerBase
{
    private const string LabUserHeaderName = "X-Lab-User-Id";

    private readonly GetA02SecretExportQueryHandler _getSecretExportQueryHandler;
    private readonly ILogger<A02CryptographicFailuresController> _logger;

    public A02CryptographicFailuresController(
        GetA02SecretExportQueryHandler getSecretExportQueryHandler,
        ILogger<A02CryptographicFailuresController> logger)
    {
        _getSecretExportQueryHandler = getSecretExportQueryHandler;
        _logger = logger;
    }

    [HttpGet("secrets/export")]
    public async Task<ActionResult<A02SecretExportResponse>> ExportSecret(CancellationToken cancellationToken)
    {
        var currentUserId = GetCurrentUserId();

        _logger.LogInformation(
            "Running A02 secret export scenario for lab user {UserId}",
            currentUserId);

        var result = await _getSecretExportQueryHandler.Handle(
            new GetA02SecretExportQuery(currentUserId),
            cancellationToken);

        return ToActionResult(result);
    }

    private ActionResult<A02SecretExportResponse> ToActionResult(A02SecretExportResponse response)
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
