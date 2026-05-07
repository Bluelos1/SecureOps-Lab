using System.Text.RegularExpressions;
using SecureOpsLab.Application.Common.CloudLogging;

namespace SecureOpsLab.Api.Security;

public sealed class SecurityDetectionMiddleware
{
    private const string LabUserHeaderName = "X-Lab-User-Id";
    private readonly RequestDelegate _next;
    private readonly ILogger<SecurityDetectionMiddleware> _logger;

    private static readonly IReadOnlyList<DetectionRule> Rules =
    [
        new(
            "LAB-GENERIC-SQLI",
            "SuspiciousHttpInput",
            "High",
            "SQL injection pattern",
            new Regex(@"('|%27)\s*(or|and)\s+\d+\s*=\s*\d+|--|/\*|\bunion\s+select\b|\bsleep\s*\(|\bdrop\s+table\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        new(
            "LAB-GENERIC-XSS",
            "SuspiciousHttpInput",
            "Medium",
            "XSS pattern",
            new Regex(@"<\s*script|%3c\s*script|javascript:\s*|onerror\s*=|onload\s*=", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        new(
            "LAB-GENERIC-TRAVERSAL",
            "SuspiciousHttpInput",
            "Medium",
            "path traversal pattern",
            new Regex(@"\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        new(
            "LAB-GENERIC-SSRF",
            "SuspiciousHttpInput",
            "High",
            "SSRF/internal target pattern",
            new Regex(@"https?://(localhost|localstack|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[0-1])\.)", RegexOptions.IgnoreCase | RegexOptions.Compiled))
    ];

    public SecurityDetectionMiddleware(
        RequestDelegate next,
        ILogger<SecurityDetectionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, ILabCloudAuditLog cloudAuditLog)
    {
        var inspectedValue = BuildInspectedValue(context.Request);
        var matchedRule = Rules.FirstOrDefault(rule => rule.Pattern.IsMatch(inspectedValue));

        if (matchedRule is not null)
        {
            await WriteDetectionAsync(context, cloudAuditLog, matchedRule, inspectedValue);
        }

        await _next(context);
    }

    private async Task WriteDetectionAsync(
        HttpContext context,
        ILabCloudAuditLog cloudAuditLog,
        DetectionRule matchedRule,
        string inspectedValue)
    {
        try
        {
            var userId = GetCurrentUserId(context.Request);
            var targetId = $"{context.Request.Method} {context.Request.Path}";
            var details = $"Generic HTTP detector matched {matchedRule.Description}. Input: {Truncate(inspectedValue, 500)}";

            await cloudAuditLog.WriteAsync(new LabCloudAuditEvent
            {
                EventType = matchedRule.EventType,
                RuleId = matchedRule.RuleId,
                Severity = matchedRule.Severity,
                UserId = userId,
                TargetType = "HttpRequest",
                TargetId = targetId,
                Result = "Observed",
                Details = details,
                OccurredAtUtc = DateTime.UtcNow
            }, context.RequestAborted);

            _logger.LogWarning(
                "{RuleId} matched suspicious HTTP input for {Method} {Path}",
                matchedRule.RuleId,
                context.Request.Method,
                context.Request.Path);
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Failed to write generic security detection to LocalStack CloudWatch Logs");
        }
    }

    private static string BuildInspectedValue(HttpRequest request)
    {
        var raw = $"{request.Path}{request.QueryString}";
        return Uri.UnescapeDataString(raw);
    }

    private static Guid? GetCurrentUserId(HttpRequest request)
    {
        if (request.Headers.TryGetValue(LabUserHeaderName, out var value) &&
            Guid.TryParse(value, out var parsed))
        {
            return parsed;
        }

        return null;
    }

    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength];
    }

    private sealed record DetectionRule(
        string RuleId,
        string EventType,
        string Severity,
        string Description,
        Regex Pattern);
}
