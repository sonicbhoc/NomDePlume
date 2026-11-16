namespace NomDePlume.SignatureVerification;

public readonly record struct AssemblyFileNotFound(FilePath Path);

public readonly record struct CorHeaderNotFound(FilePath Path);

public readonly record struct CorStrongNameFlagUnset(FilePath Path);
public readonly record struct PEHeaderEmpty(FilePath Path);
public readonly record struct NotAnAssembly(FilePath Path);

public union SignatureVerificationResult(AssemblyFileNotFound, CorHeaderNotFound, CorStrongNameFlagUnset, PEHeaderEmpty, NotAnAssembly);
