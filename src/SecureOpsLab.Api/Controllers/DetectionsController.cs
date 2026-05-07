using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Detections;
using SecureOpsLab.Contracts.Detections;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/detections")]
public sealed class DetectionsController : ControllerBase
{
    private readonly GetCloudDetectionSummaryQueryHandler _cloudDetectionSummaryQueryHandler;

    public DetectionsController(GetCloudDetectionSummaryQueryHandler cloudDetectionSummaryQueryHandler)
    {
        _cloudDetectionSummaryQueryHandler = cloudDetectionSummaryQueryHandler;
    }

    [HttpGet("cloud")]
    public async Task<ActionResult<CloudDetectionSummaryResponse>> GetCloudDetections(CancellationToken cancellationToken)
    {
        var result = await _cloudDetectionSummaryQueryHandler.Handle(cancellationToken);
        return Ok(result);
    }
}
