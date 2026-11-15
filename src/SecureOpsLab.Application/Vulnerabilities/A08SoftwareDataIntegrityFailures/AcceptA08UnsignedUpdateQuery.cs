namespace SecureOpsLab.Application.Vulnerabilities.A08SoftwareDataIntegrityFailures;

public sealed record AcceptA08UnsignedUpdateQuery(Guid CurrentUserId, string PackageUrl);
