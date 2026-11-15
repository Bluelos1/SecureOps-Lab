using Microsoft.Extensions.DependencyInjection;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Detections;
using SecureOpsLab.Application.Vulnerabilities.A01BrokenAccessControl;
using SecureOpsLab.Application.Vulnerabilities.A02CryptographicFailures;
using SecureOpsLab.Application.Vulnerabilities.A03Injection;
using SecureOpsLab.Application.Vulnerabilities.A04InsecureDesign;
using SecureOpsLab.Application.Vulnerabilities.A05SecurityMisconfiguration;
using SecureOpsLab.Application.Vulnerabilities.A06VulnerableComponents;
using SecureOpsLab.Application.Vulnerabilities.A07IdentificationAuthenticationFailures;
using SecureOpsLab.Application.Vulnerabilities.A08SoftwareDataIntegrityFailures;
using SecureOpsLab.Application.Vulnerabilities.A09SecurityLoggingMonitoringFailures;
using SecureOpsLab.Application.Vulnerabilities.A10ServerSideRequestForgery;

namespace SecureOpsLab.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddSingleton<VulnerabilityRuntimeState>();
        services.AddScoped<GetA01DocumentsQueryHandler>();
        services.AddScoped<GetA01DocumentByIdQueryHandler>();
        services.AddScoped<GetA02SecretExportQueryHandler>();
        services.AddScoped<SearchA03DocumentsQueryHandler>();
        services.AddScoped<RequestA04EmergencyAccessQueryHandler>();
        services.AddScoped<GetA05ObjectByDocumentIdQueryHandler>();
        services.AddScoped<RenderA06LegacyComponentQueryHandler>();
        services.AddScoped<GetA07DefaultLoginQueryHandler>();
        services.AddScoped<AcceptA08UnsignedUpdateQueryHandler>();
        services.AddScoped<RunA09SensitiveExportQueryHandler>();
        services.AddScoped<GetA10ServerSideRequestForgeryQueryHandler>();
        services.AddScoped<GetCloudDetectionSummaryQueryHandler>();

        return services;
    }
}
