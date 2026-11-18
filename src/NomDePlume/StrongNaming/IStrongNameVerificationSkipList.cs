namespace NomDePlume.StrongNaming;

public interface IStrongNameVerificationSkipList
{
    bool IsVerificationSkipped(FilePath assemblyPath, string assemblyName, string publicKeyToken);
}
