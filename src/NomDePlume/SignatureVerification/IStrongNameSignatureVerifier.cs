namespace NomDePlume.SignatureVerification;

public interface IStrongNameSignatureVerifier
{
    Task<SignatureVerificationResult> VerifyAssemblyStrongNamingAsync(FilePath assemblyPath);
}
