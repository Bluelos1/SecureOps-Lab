using SecureOpsLab.Api.Security;
using SecureOpsLab.Application;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Infrastructure;
using SecureOpsLab.Infrastructure.CloudLogging;
using SecureOpsLab.Infrastructure.Persistence;
using SecureOpsLab.Infrastructure.Storage;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, configuration) =>
{
    configuration
        .ReadFrom.Configuration(context.Configuration)
        .Enrich.FromLogContext();
});

builder.Services.AddOptions<SecurityLabOptions>()
    .Bind(builder.Configuration.GetSection(SecurityLabOptions.SectionName))
    .ValidateOnStart();

builder.Services.AddApplication();
builder.Services.AddInfrastructure(builder.Configuration);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

await app.Services.SeedLabDatabaseAsync();
await app.Services.SeedLabObjectStorageAsync();
await app.Services.SeedLabCloudLoggingAsync();

app.UseSerilogRequestLogging();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseMiddleware<SecurityDetectionMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.MapControllers();

app.Run();
