using DotMake.CommandLine;

namespace NomDePlume.SignatureVerification;

public interface IStrongNameSignatureVerifier
{
    SignatureVerificationResult VerifyAssemblyStrongNaming(FilePath assemblyPath, bool force = false);
}
