using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/vulnerabilities")]
public sealed class VulnerabilitiesController : ControllerBase
{
    private readonly VulnerabilityRuntimeState _vulnerabilityState;

    public VulnerabilitiesController(VulnerabilityRuntimeState vulnerabilityState)
    {
        _vulnerabilityState = vulnerabilityState;
    }

    [HttpGet]
    public ActionResult<IReadOnlyList<VulnerabilityModuleResponse>> GetAll()
    {
        return Ok(GetModules());
    }

    [HttpPut("{id}/enabled")]
    public ActionResult<IReadOnlyList<VulnerabilityModuleResponse>> Update(
        string id,
        UpdateVulnerabilityStateRequest request)
    {
        if (!_vulnerabilityState.TrySet(id, request.Enabled))
        {
            return NotFound();
        }

        return Ok(GetModules());
    }

    private IReadOnlyList<VulnerabilityModuleResponse> GetModules()
    {
        return new[]
        {
            new VulnerabilityModuleResponse
            {
                Id = "A01-IDOR",
                Name = "Broken Access Control / IDOR",
                OwaspCategory = "A01 Broken Access Control",
                Route = "GET /api/vulnerabilities/a01-broken-access-control/documents/{id}",
                Enabled = _vulnerabilityState.A01BrokenAccessControl,
                Description = "Alice can try to read Bob's document by changing the document id in the URL."
            },
            new VulnerabilityModuleResponse
            {
                Id = "A03-SQLI",
                Name = "Injection / SQL Injection",
                OwaspCategory = "A03 Injection",
                Route = "GET /api/vulnerabilities/a03-injection/documents/search?term={term}",
                Enabled = _vulnerabilityState.A03Injection,
                Description = "Alice can try to bypass document search filtering by injecting SQL into the search term."
            },
            new VulnerabilityModuleResponse
            {
                Id = "A05-S3",
                Name = "Security Misconfiguration / Object Storage",
                OwaspCategory = "A05 Security Misconfiguration",
                Route = "GET /api/vulnerabilities/a05-security-misconfiguration/objects/{documentId}",
                Enabled = _vulnerabilityState.A05SecurityMisconfiguration,
                Description = "Alice can try to fetch Bob's LocalStack S3 object when object ownership is not checked."
            },
            new VulnerabilityModuleResponse
            {
                Id = "A10-SSRF",
                Name = "Server-Side Request Forgery",
                OwaspCategory = "A10 Server-Side Request Forgery",
                Route = "GET /api/vulnerabilities/a10-ssrf/fetch?url={url}",
                Enabled = _vulnerabilityState.A10ServerSideRequestForgery,
                Description = "A user can try to make the server fetch internal LocalStack endpoints."
            }
        };
    }
}
