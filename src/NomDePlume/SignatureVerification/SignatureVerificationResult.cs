using System.Runtime.CompilerServices;

namespace NomDePlume.SignatureVerification;

[Union]
public readonly struct SignatureVerificationResult : IUnion
{
    private enum Case : byte
    {
        None,
        AssemblyFileNotFound,
        StrongNameHasherError,
        CorStrongNameFlagUnset,
        StrongNameSignatureInvalid,
        StrongNameSignatureValid,
        StrongNameVerificationSkipped
    }

    private readonly Case _caseType;
    private readonly FilePath _path;
    private readonly StrongNameHasherError _hasherError;

    public SignatureVerificationResult(AssemblyFileNotFound value)
    {
        _caseType = Case.AssemblyFileNotFound;
        _path = value.Path;
        _hasherError = default;
    }

    public SignatureVerificationResult(StrongNameHasherError value)
    {
        _caseType = Case.StrongNameHasherError;
        _path = default;
        _hasherError = value;
    }

    public SignatureVerificationResult(CorStrongNameFlagUnset value)
    {
        _caseType = Case.CorStrongNameFlagUnset;
        _path = value.Path;
        _hasherError = default;
    }

    public SignatureVerificationResult(StrongNameSignatureInvalid value)
    {
        _caseType = Case.StrongNameSignatureInvalid;
        _path = value.Path;
        _hasherError = default;
    }

    public SignatureVerificationResult(StrongNameSignatureValid value)
    {
        _caseType = Case.StrongNameSignatureValid;
        _path = value.Path;
        _hasherError = default;
    }

    public SignatureVerificationResult(StrongNameVerificationSkipped value)
    {
        _caseType = Case.StrongNameVerificationSkipped;
        _path = value.Path;
        _hasherError = default;
    }

    public object? Value => _caseType switch
    {
        Case.None => null,
        Case.AssemblyFileNotFound => new AssemblyFileNotFound(_path),
        Case.StrongNameHasherError => _hasherError,
        Case.CorStrongNameFlagUnset => new CorStrongNameFlagUnset(_path),
        Case.StrongNameSignatureInvalid => new StrongNameSignatureInvalid(_path),
        Case.StrongNameSignatureValid => new StrongNameSignatureValid(_path),
        Case.StrongNameVerificationSkipped => new StrongNameVerificationSkipped(_path),
        _ => throw new InvalidOperationException("The signature verification result has an unknown case.")
    };

    public bool HasValue => _caseType != Case.None;

    public bool TryGetValue(out AssemblyFileNotFound value)
        => TryGetPath(Case.AssemblyFileNotFound, out value);

    public bool TryGetValue(out StrongNameHasherError value)
    {
        bool found = _caseType == Case.StrongNameHasherError;
        value = found ? _hasherError : default;
        return found;
    }

    public bool TryGetValue(out CorStrongNameFlagUnset value)
        => TryGetPath(Case.CorStrongNameFlagUnset, out value);

    public bool TryGetValue(out StrongNameSignatureInvalid value)
        => TryGetPath(Case.StrongNameSignatureInvalid, out value);

    public bool TryGetValue(out StrongNameSignatureValid value)
        => TryGetPath(Case.StrongNameSignatureValid, out value);

    public bool TryGetValue(out StrongNameVerificationSkipped value)
        => TryGetPath(Case.StrongNameVerificationSkipped, out value);

    private bool TryGetPath(Case expectedCase, out AssemblyFileNotFound value)
    {
        bool found = _caseType == expectedCase;
        value = found ? new AssemblyFileNotFound(_path) : default;
        return found;
    }

    private bool TryGetPath(Case expectedCase, out CorStrongNameFlagUnset value)
    {
        bool found = _caseType == expectedCase;
        value = found ? new CorStrongNameFlagUnset(_path) : default;
        return found;
    }

    private bool TryGetPath(Case expectedCase, out StrongNameSignatureInvalid value)
    {
        bool found = _caseType == expectedCase;
        value = found ? new StrongNameSignatureInvalid(_path) : default;
        return found;
    }

    private bool TryGetPath(Case expectedCase, out StrongNameSignatureValid value)
    {
        bool found = _caseType == expectedCase;
        value = found ? new StrongNameSignatureValid(_path) : default;
        return found;
    }

    private bool TryGetPath(Case expectedCase, out StrongNameVerificationSkipped value)
    {
        bool found = _caseType == expectedCase;
        value = found ? new StrongNameVerificationSkipped(_path) : default;
        return found;
    }
}

public readonly record struct AssemblyFileNotFound(FilePath Path);

public readonly record struct CorStrongNameFlagUnset(FilePath Path);

public readonly record struct StrongNameSignatureInvalid(FilePath Path);

public readonly record struct StrongNameSignatureValid(FilePath Path);

public readonly record struct StrongNameVerificationSkipped(FilePath Path);
