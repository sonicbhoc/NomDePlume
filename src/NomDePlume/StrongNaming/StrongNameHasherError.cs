using System.Runtime.CompilerServices;

namespace NomDePlume.StrongNaming;

[Union]
public readonly struct StrongNameHasherError : IUnion
{
    private enum Case : byte
    {
        None,
        PEHeaderEmpty,
        NotAnAssembly,
        CorHeaderNotFound,
        StrongNamePublicKeyMissing,
        UnsupportedStrongNameHashAlgorithm,
        InvalidStrongNameSignatureDirectory,
        InvalidStrongNamePublicKey,
        InvalidStrongNameImage
    }

    private readonly Case _caseType;
    private readonly FilePath _path;
    private readonly string? _detail;

    public StrongNameHasherError(PEHeaderEmpty value)
    {
        _caseType = Case.PEHeaderEmpty;
        _path = value.Path;
        _detail = null;
    }

    public StrongNameHasherError(NotAnAssembly value)
    {
        _caseType = Case.NotAnAssembly;
        _path = value.Path;
        _detail = null;
    }

    public StrongNameHasherError(CorHeaderNotFound value)
    {
        _caseType = Case.CorHeaderNotFound;
        _path = value.Path;
        _detail = null;
    }

    public StrongNameHasherError(StrongNamePublicKeyMissing value)
    {
        _caseType = Case.StrongNamePublicKeyMissing;
        _path = value.Path;
        _detail = null;
    }

    public StrongNameHasherError(UnsupportedStrongNameHashAlgorithm value)
    {
        _caseType = Case.UnsupportedStrongNameHashAlgorithm;
        _path = value.Path;
        _detail = value.Algorithm;
    }

    public StrongNameHasherError(InvalidStrongNameSignatureDirectory value)
    {
        _caseType = Case.InvalidStrongNameSignatureDirectory;
        _path = value.Path;
        _detail = value.Reason;
    }

    public StrongNameHasherError(InvalidStrongNamePublicKey value)
    {
        _caseType = Case.InvalidStrongNamePublicKey;
        _path = value.Path;
        _detail = value.Reason;
    }

    public StrongNameHasherError(InvalidStrongNameImage value)
    {
        _caseType = Case.InvalidStrongNameImage;
        _path = value.Path;
        _detail = value.Reason;
    }

    public object? Value => _caseType switch
    {
        Case.None => null,
        Case.PEHeaderEmpty => new PEHeaderEmpty(_path),
        Case.NotAnAssembly => new NotAnAssembly(_path),
        Case.CorHeaderNotFound => new CorHeaderNotFound(_path),
        Case.StrongNamePublicKeyMissing => new StrongNamePublicKeyMissing(_path),
        Case.UnsupportedStrongNameHashAlgorithm => new UnsupportedStrongNameHashAlgorithm(_path, _detail!),
        Case.InvalidStrongNameSignatureDirectory => new InvalidStrongNameSignatureDirectory(_path, _detail!),
        Case.InvalidStrongNamePublicKey => new InvalidStrongNamePublicKey(_path, _detail!),
        Case.InvalidStrongNameImage => new InvalidStrongNameImage(_path, _detail!),
        _ => throw new InvalidOperationException("The strong-name hash error has an unknown case.")
    };

    public bool HasValue => _caseType != Case.None;

    public bool TryGetValue(out PEHeaderEmpty value)
        => TryGetPath(Case.PEHeaderEmpty, out value);

    public bool TryGetValue(out NotAnAssembly value)
        => TryGetPath(Case.NotAnAssembly, out value);

    public bool TryGetValue(out CorHeaderNotFound value)
        => TryGetPath(Case.CorHeaderNotFound, out value);

    public bool TryGetValue(out StrongNamePublicKeyMissing value)
        => TryGetPath(Case.StrongNamePublicKeyMissing, out value);

    public bool TryGetValue(out UnsupportedStrongNameHashAlgorithm value)
    {
        bool found = TryGetDetail(Case.UnsupportedStrongNameHashAlgorithm, out string detail);
        value = found ? new UnsupportedStrongNameHashAlgorithm(_path, detail) : default;
        return found;
    }

    public bool TryGetValue(out InvalidStrongNameSignatureDirectory value)
    {
        bool found = TryGetDetail(Case.InvalidStrongNameSignatureDirectory, out string detail);
        value = found ? new InvalidStrongNameSignatureDirectory(_path, detail) : default;
        return found;
    }

    public bool TryGetValue(out InvalidStrongNamePublicKey value)
    {
        bool found = TryGetDetail(Case.InvalidStrongNamePublicKey, out string detail);
        value = found ? new InvalidStrongNamePublicKey(_path, detail) : default;
        return found;
    }

    public bool TryGetValue(out InvalidStrongNameImage value)
    {
        bool found = TryGetDetail(Case.InvalidStrongNameImage, out string detail);
        value = found ? new InvalidStrongNameImage(_path, detail) : default;
        return found;
    }

    private bool TryGetPath(Case expectedCase, out PEHeaderEmpty value)
    {
        bool found = _caseType == expectedCase;
        value = found ? new PEHeaderEmpty(_path) : default;
        return found;
    }

    private bool TryGetPath(Case expectedCase, out NotAnAssembly value)
    {
        bool found = _caseType == expectedCase;
        value = found ? new NotAnAssembly(_path) : default;
        return found;
    }

    private bool TryGetPath(Case expectedCase, out CorHeaderNotFound value)
    {
        bool found = _caseType == expectedCase;
        value = found ? new CorHeaderNotFound(_path) : default;
        return found;
    }

    private bool TryGetPath(Case expectedCase, out StrongNamePublicKeyMissing value)
    {
        bool found = _caseType == expectedCase;
        value = found ? new StrongNamePublicKeyMissing(_path) : default;
        return found;
    }

    private bool TryGetDetail(Case expectedCase, out string detail)
    {
        bool found = _caseType == expectedCase;
        detail = found ? _detail! : string.Empty;
        return found;
    }
}

public readonly record struct PEHeaderEmpty(FilePath Path);

public readonly record struct NotAnAssembly(FilePath Path);

public readonly record struct CorHeaderNotFound(FilePath Path);

public readonly record struct StrongNamePublicKeyMissing(FilePath Path);

public readonly record struct UnsupportedStrongNameHashAlgorithm(FilePath Path, string Algorithm);

public readonly record struct InvalidStrongNameSignatureDirectory(FilePath Path, string Reason);

public readonly record struct InvalidStrongNamePublicKey(FilePath Path, string Reason);

public readonly record struct InvalidStrongNameImage(FilePath Path, string Reason);
