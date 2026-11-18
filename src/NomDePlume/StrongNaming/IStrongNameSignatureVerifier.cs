namespace NomDePlume.StrongNaming;

public interface IStrongNameSignatureVerifier
{
    Task<StrongNameSignatureVerificationResult> VerifyAssemblyStrongNamingAsync(
        FilePath assemblyPath,
        bool force = false);
}
