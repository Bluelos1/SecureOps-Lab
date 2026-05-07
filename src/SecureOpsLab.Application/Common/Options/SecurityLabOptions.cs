namespace SecureOpsLab.Application.Common.Options;

public sealed class SecurityLabOptions
{
    public const string SectionName = "SecurityLab";

    public VulnerabilityOptions Vulnerabilities { get; set; } = new();
    public ObjectStorageOptions ObjectStorage { get; set; } = new();
    public CloudLoggingOptions CloudLogging { get; set; } = new();
}

public sealed class VulnerabilityOptions
{
    public bool A01BrokenAccessControl { get; set; }
    public bool A03Injection { get; set; }
    public bool A05SecurityMisconfiguration { get; set; }
    public bool A10ServerSideRequestForgery { get; set; }
}

public sealed class ObjectStorageOptions
{
    public string ServiceUrl { get; set; } = "http://localhost:4566";
    public string Region { get; set; } = "us-east-1";
    public string BucketName { get; set; } = "secureops-lab-documents";
    public string AccessKey { get; set; } = "test";
    public string SecretKey { get; set; } = "test";
}

public sealed class CloudLoggingOptions
{
    public string ServiceUrl { get; set; } = "http://localhost:4566";
    public string Region { get; set; } = "us-east-1";
    public string LogGroupName { get; set; } = "/secureops-lab/security-events";
    public string LogStreamName { get; set; } = "lab-runtime";
    public string AccessKey { get; set; } = "test";
    public string SecretKey { get; set; } = "test";
}
