namespace SecureOpsLab.Application.Vulnerabilities.A01BrokenAccessControl;

public sealed record GetA01DocumentByIdQuery(Guid DocumentId, Guid CurrentUserId);
