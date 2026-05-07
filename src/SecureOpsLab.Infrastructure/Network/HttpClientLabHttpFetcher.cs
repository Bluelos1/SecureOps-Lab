using SecureOpsLab.Application.Common.Network;

namespace SecureOpsLab.Infrastructure.Network;

public sealed class HttpClientLabHttpFetcher : ILabHttpFetcher
{
    private const int MaxBodyPreviewLength = 3000;

    private readonly HttpClient _httpClient;

    public HttpClientLabHttpFetcher(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<LabHttpFetchResult> FetchAsync(Uri uri, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        using var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (body.Length > MaxBodyPreviewLength)
        {
            body = body[..MaxBodyPreviewLength];
        }

        return new LabHttpFetchResult(
            (int)response.StatusCode,
            response.Content.Headers.ContentType?.ToString() ?? string.Empty,
            body);
    }
}
