using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureOpsLab.Application.Common;
using SecureOpsLab.Application.Common.Options;
using SecureOpsLab.Application.Common.Storage;

namespace SecureOpsLab.Infrastructure.Storage;

public static class ObjectStorageSeeder
{
    public static async Task SeedLabObjectStorageAsync(this IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var s3Client = scope.ServiceProvider.GetRequiredService<IAmazonS3>();
        var options = scope.ServiceProvider.GetRequiredService<IOptions<SecurityLabOptions>>().Value.ObjectStorage;
        var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>()
            .CreateLogger("SecureOpsLab.Infrastructure.Storage.ObjectStorageSeeder");

        for (var attempt = 1; attempt <= 12; attempt++)
        {
            try
            {
                await SeedCoreAsync(s3Client, options, CancellationToken.None);
                logger.LogInformation(
                    "Seeded LocalStack S3 bucket {BucketName} for lab object storage",
                    options.BucketName);
                return;
            }
            catch (AmazonS3Exception) when (attempt < 12)
            {
                logger.LogWarning(
                    "LocalStack S3 is not ready yet. Retrying object storage seed, attempt {Attempt}/12",
                    attempt);
                await Task.Delay(TimeSpan.FromSeconds(2));
            }
        }

        await SeedCoreAsync(s3Client, options, CancellationToken.None);
    }

    private static async Task SeedCoreAsync(
        IAmazonS3 s3Client,
        ObjectStorageOptions options,
        CancellationToken cancellationToken)
    {
        await EnsureBucketAsync(s3Client, options.BucketName, cancellationToken);

        await PutObjectAsync(
            s3Client,
            options.BucketName,
            LabObjectKeys.ForDocument(LabSeedIds.AliceDocumentId),
            "LocalStack S3 artefact for Alice's private document. Bob should not read this object in safe mode.",
            cancellationToken);

        await PutObjectAsync(
            s3Client,
            options.BucketName,
            LabObjectKeys.ForDocument(LabSeedIds.BobDocumentId),
            "LocalStack S3 artefact for Bob's confidential document. Alice should only read this in vulnerable A05 mode.",
            cancellationToken);
    }

    private static async Task EnsureBucketAsync(
        IAmazonS3 s3Client,
        string bucketName,
        CancellationToken cancellationToken)
    {
        try
        {
            await s3Client.PutBucketAsync(new PutBucketRequest
            {
                BucketName = bucketName
            }, cancellationToken);
        }
        catch (AmazonS3Exception exception) when (exception.ErrorCode is "BucketAlreadyOwnedByYou" or "BucketAlreadyExists")
        {
        }
    }

    private static async Task PutObjectAsync(
        IAmazonS3 s3Client,
        string bucketName,
        string objectKey,
        string content,
        CancellationToken cancellationToken)
    {
        await s3Client.PutObjectAsync(new PutObjectRequest
        {
            BucketName = bucketName,
            Key = objectKey,
            ContentBody = content,
            ContentType = "text/plain"
        }, cancellationToken);
    }
}
