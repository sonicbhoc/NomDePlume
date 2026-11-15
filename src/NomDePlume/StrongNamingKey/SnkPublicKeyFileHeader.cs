using NomDePlume.Capi;

namespace NomDePlume.StrongNamingKey;

/// <summary>
/// Hash algorithm ID. CALG_SHA1 (0x8004) is standard; 0 defaults to SHA-1.
/// </summary>
/// <remarks>
/// Public key tokens always use SHA-1 regardless of this field.
/// </remarks>
public enum KeyHashAlgorithm : uint
{
    DEFAULT = 0x0,
    CALG_SHA1 = 0x00008004,
    CALG_SHA_256 = 0x0000800C
}

public struct SnkPublicKeyFileHeader
{
    public KeySigningAlgorithm KeySigningAlgorithm { get; internal set; }
    public KeyHashAlgorithm KeyHashAlgorithm { get; internal set; }
    public uint PublicKeySize { get; internal set; }
}
