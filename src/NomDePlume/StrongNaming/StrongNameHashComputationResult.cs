using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace NomDePlume.StrongNaming;

public readonly record struct StrongNameHashData(
    byte[] Hash,
    HashAlgorithmName AlgorithmName,
    int SignatureOffset,
    int SignatureLength);

[Union]
public readonly struct StrongNameHashComputationResult : IUnion
{
    private enum Case : byte
    {
        None,
        Data,
        Error
    }

    private readonly Case _caseType;
    private readonly StrongNameHashData _data;
    private readonly StrongNameHasherError _error;

    public StrongNameHashComputationResult(StrongNameHashData data)
    {
        _caseType = Case.Data;
        _data = data;
        _error = default;
    }

    public StrongNameHashComputationResult(StrongNameHasherError error)
    {
        _caseType = Case.Error;
        _data = default;
        _error = error;
    }

    public object? Value => _caseType switch
    {
        Case.None => null,
        Case.Data => _data,
        Case.Error => _error,
        _ => throw new InvalidOperationException("The strong-name hash result has an unknown case.")
    };

    public bool HasValue => _caseType != Case.None;

    public bool TryGetValue(out StrongNameHashData value)
    {
        bool found = _caseType == Case.Data;
        value = found ? _data : default;
        return found;
    }

    public bool TryGetValue(out StrongNameHasherError value)
    {
        bool found = _caseType == Case.Error;
        value = found ? _error : default;
        return found;
    }
}
