namespace SecureOpsLab.Application.Vulnerabilities.A07IdentificationAuthenticationFailures;

public sealed record GetA07DefaultLoginQuery(Guid CurrentUserId, string Password);
