namespace SecureOpsLab.Application.Common.Storage;

public interface ILabObjectStorage
{
    Task<string?> ReadTextObjectAsync(string objectKey, CancellationToken cancellationToken);
}
