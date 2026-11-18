namespace NomDePlume.SignatureVerification;

public interface SignatureVerificationResult
{
}

public readonly record struct AssemblyFileNotFound(string Path) : SignatureVerificationResult;

public readonly record struct CorHeaderNotFound(string Path) : SignatureVerificationResult;

public readonly record struct CorStrongNameFlagUnset(string Path) : SignatureVerificationResult;

public readonly record struct PEHeaderEmpty(string Path) : SignatureVerificationResult;

public readonly record struct NotAnAssembly(string Path) : SignatureVerificationResult;

public readonly record struct StrongNameSignatureInvalid(string Path) : SignatureVerificationResult;

public readonly record struct StrongNameSignatureValid(string Path) : SignatureVerificationResult;

public readonly record struct StrongNameVerificationSkipped(string Path) : SignatureVerificationResult;
