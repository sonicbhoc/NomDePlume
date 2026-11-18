namespace NomDePlume.StrongNaming;

public interface IStrongNameVerificationSkipList
{
    bool IsVerificationSkipped(string assemblyPath, string assemblyName, string publicKeyToken);
}
