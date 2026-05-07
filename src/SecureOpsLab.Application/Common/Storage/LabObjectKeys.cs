namespace SecureOpsLab.Application.Common.Storage;

public static class LabObjectKeys
{
    public static string ForDocument(Guid documentId)
    {
        return $"documents/{documentId:D}/evidence.txt";
    }
}
