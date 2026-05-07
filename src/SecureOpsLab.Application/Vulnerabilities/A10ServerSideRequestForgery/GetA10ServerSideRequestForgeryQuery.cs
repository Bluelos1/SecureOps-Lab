namespace SecureOpsLab.Application.Vulnerabilities.A10ServerSideRequestForgery;

public sealed record GetA10ServerSideRequestForgeryQuery(string TargetUrl, Guid CurrentUserId);
