using Microsoft.Extensions.DependencyInjection;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Detections;
using SecureOpsLab.Application.Vulnerabilities.A01BrokenAccessControl;
using SecureOpsLab.Application.Vulnerabilities.A03Injection;
using SecureOpsLab.Application.Vulnerabilities.A05SecurityMisconfiguration;
using SecureOpsLab.Application.Vulnerabilities.A10ServerSideRequestForgery;

namespace SecureOpsLab.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddSingleton<VulnerabilityRuntimeState>();
        services.AddScoped<GetA01DocumentsQueryHandler>();
        services.AddScoped<GetA01DocumentByIdQueryHandler>();
        services.AddScoped<SearchA03DocumentsQueryHandler>();
        services.AddScoped<GetA05ObjectByDocumentIdQueryHandler>();
        services.AddScoped<GetA10ServerSideRequestForgeryQueryHandler>();
        services.AddScoped<GetCloudDetectionSummaryQueryHandler>();

        return services;
    }
}
