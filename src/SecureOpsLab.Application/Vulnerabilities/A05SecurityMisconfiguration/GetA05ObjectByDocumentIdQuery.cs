namespace SecureOpsLab.Application.Vulnerabilities.A05SecurityMisconfiguration;

public sealed record GetA05ObjectByDocumentIdQuery(Guid DocumentId, Guid CurrentUserId);
