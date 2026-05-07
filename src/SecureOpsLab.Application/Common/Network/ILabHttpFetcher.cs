namespace SecureOpsLab.Application.Common.Network;

public interface ILabHttpFetcher
{
    Task<LabHttpFetchResult> FetchAsync(Uri uri, CancellationToken cancellationToken);
}

public sealed record LabHttpFetchResult(
    int StatusCode,
    string ContentType,
    string BodyPreview);
