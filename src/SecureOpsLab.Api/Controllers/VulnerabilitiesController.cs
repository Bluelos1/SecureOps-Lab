using Microsoft.AspNetCore.Mvc;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Vulnerabilities;
using SecureOpsLab.Contracts.Vulnerabilities;

namespace SecureOpsLab.Api.Controllers;

[ApiController]
[Route("api/vulnerabilities")]
public sealed class VulnerabilitiesController : ControllerBase
{
    private static readonly IReadOnlyList<ModuleDefinition> ModuleDefinitions =
    [
        new(
            VulnerabilityModuleIds.A01Idor,
            "Broken Access Control / IDOR",
            "A01 Broken Access Control",
            "GET /api/vulnerabilities/a01-broken-access-control/documents/{id}",
            state => state.A01BrokenAccessControl,
            "Alice can try to read Bob's document by changing the document id in the URL."),
        new(
            VulnerabilityModuleIds.A02Crypto,
            "Cryptographic Failures / Secret Exposure",
            "A02 Cryptographic Failures",
            "GET /api/vulnerabilities/a02-cryptographic-failures/secrets/export",
            state => state.A02CryptographicFailures,
            "A user can try to export a plaintext lab backup token that should be encrypted or redacted."),
        new(
            VulnerabilityModuleIds.A03Sqli,
            "Injection / SQL Injection",
            "A03 Injection",
            "GET /api/vulnerabilities/a03-injection/documents/search?term={term}",
            state => state.A03Injection,
            "Alice can try to bypass document search filtering by injecting SQL into the search term."),
        new(
            VulnerabilityModuleIds.A04Design,
            "Insecure Design / Approval Bypass",
            "A04 Insecure Design",
            "GET /api/vulnerabilities/a04-insecure-design/emergency-access",
            state => state.A04InsecureDesign,
            "A user can try to obtain emergency access without an approval step."),
        new(
            VulnerabilityModuleIds.A05S3,
            "Security Misconfiguration / Object Storage",
            "A05 Security Misconfiguration",
            "GET /api/vulnerabilities/a05-security-misconfiguration/objects/{documentId}",
            state => state.A05SecurityMisconfiguration,
            "Alice can try to fetch Bob's LocalStack S3 object when object ownership is not checked."),
        new(
            VulnerabilityModuleIds.A06Components,
            "Vulnerable and Outdated Components",
            "A06 Vulnerable and Outdated Components",
            "GET /api/vulnerabilities/a06-vulnerable-components/render?payload={payload}",
            state => state.A06VulnerableComponents,
            "A user can try to send an exploit marker to a simulated legacy component."),
        new(
            VulnerabilityModuleIds.A07Auth,
            "Identification and Authentication Failures",
            "A07 Identification and Authentication Failures",
            "GET /api/vulnerabilities/a07-identification-authentication/default-login?password={password}",
            state => state.A07IdentificationAuthenticationFailures,
            "A user can try to authenticate with a default lab password."),
        new(
            VulnerabilityModuleIds.A08Integrity,
            "Software and Data Integrity Failures",
            "A08 Software and Data Integrity Failures",
            "GET /api/vulnerabilities/a08-software-data-integrity/update?packageUrl={url}",
            state => state.A08SoftwareDataIntegrityFailures,
            "A user can try to make the application accept an unsigned plugin update."),
        new(
            VulnerabilityModuleIds.A09Logging,
            "Security Logging and Monitoring Failures",
            "A09 Security Logging and Monitoring Failures",
            "GET /api/vulnerabilities/a09-logging-monitoring/admin-export",
            state => state.A09SecurityLoggingMonitoringFailures,
            "A user can try to perform a sensitive action that is not written to CloudWatch Logs in vulnerable mode."),
        new(
            VulnerabilityModuleIds.A10Ssrf,
            "Server-Side Request Forgery",
            "A10 Server-Side Request Forgery",
            "GET /api/vulnerabilities/a10-ssrf/fetch?url={url}",
            state => state.A10ServerSideRequestForgery,
            "A user can try to make the server fetch internal LocalStack endpoints.")
    ];

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
        return ModuleDefinitions
            .Select(module => module.ToResponse(_vulnerabilityState))
            .ToList();
    }

    private sealed record ModuleDefinition(
        string Id,
        string Name,
        string OwaspCategory,
        string Route,
        Func<VulnerabilityRuntimeState, bool> IsEnabled,
        string Description)
    {
        public VulnerabilityModuleResponse ToResponse(VulnerabilityRuntimeState state)
        {
            return new VulnerabilityModuleResponse
            {
                Id = Id,
                Name = Name,
                OwaspCategory = OwaspCategory,
                Route = Route,
                Enabled = IsEnabled(state),
                Description = Description
            };
        }
    }
}
