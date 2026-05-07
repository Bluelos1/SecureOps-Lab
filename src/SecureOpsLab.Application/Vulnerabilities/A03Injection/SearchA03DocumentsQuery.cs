namespace SecureOpsLab.Application.Vulnerabilities.A03Injection;

public sealed record SearchA03DocumentsQuery(string SearchTerm, Guid CurrentUserId);
