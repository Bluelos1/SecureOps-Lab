using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Common;
using SecureOpsLab.Application.Vulnerabilities.A09SecurityLoggingMonitoringFailures;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/vulnerabilities/a09-logging-monitoring")]
public sealed class A09SecurityLoggingMonitoringFailuresController : ControllerBase
{
    private const string LabUserHeaderName = "X-Lab-User-Id";

    private readonly RunA09SensitiveExportQueryHandler _runSensitiveExportQueryHandler;
    private readonly ILogger<A09SecurityLoggingMonitoringFailuresController> _logger;

    public A09SecurityLoggingMonitoringFailuresController(
        RunA09SensitiveExportQueryHandler runSensitiveExportQueryHandler,
        ILogger<A09SecurityLoggingMonitoringFailuresController> logger)
    {
        _runSensitiveExportQueryHandler = runSensitiveExportQueryHandler;
        _logger = logger;
    }

    [HttpGet("admin-export")]
    public async Task<ActionResult<A09SensitiveExportResponse>> SensitiveExport(CancellationToken cancellationToken)
    {
        var currentUserId = GetCurrentUserId();

        _logger.LogInformation(
            "Running A09 sensitive export scenario for lab user {UserId}",
            currentUserId);

        var result = await _runSensitiveExportQueryHandler.Handle(
            new RunA09SensitiveExportQuery(currentUserId),
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
