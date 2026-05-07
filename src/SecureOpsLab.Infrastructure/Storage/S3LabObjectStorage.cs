using System.Net;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Options;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Storage;

namespace SecureOpsLab.Infrastructure.Storage;

public sealed class S3LabObjectStorage : ILabObjectStorage
{
    private readonly IAmazonS3 _s3Client;
    private readonly ObjectStorageOptions _options;

    public S3LabObjectStorage(
        IAmazonS3 s3Client,
        IOptions<SecurityLabOptions> options)
    {
        _s3Client = s3Client;
        _options = options.Value.ObjectStorage;
    }

    public async Task<string?> ReadTextObjectAsync(string objectKey, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _s3Client.GetObjectAsync(
                _options.BucketName,
                objectKey,
                cancellationToken);

            using var reader = new StreamReader(response.ResponseStream);
            return await reader.ReadToEndAsync(cancellationToken);
        }
        catch (AmazonS3Exception exception) when (IsNotFound(exception))
        {
            return null;
        }
    }

    private static bool IsNotFound(AmazonS3Exception exception)
    {
        return exception.StatusCode == HttpStatusCode.NotFound ||
            exception.ErrorCode is "NoSuchBucket" or "NoSuchKey" or "NotFound";
    }
}
