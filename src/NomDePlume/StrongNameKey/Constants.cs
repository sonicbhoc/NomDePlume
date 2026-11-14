using System.Runtime.InteropServices;

namespace NomDePlume.StrongNameKey;

public enum BlobType : byte
{
    KEYSTATEBLOB = 0xC,
    OPAQUEKEYBLOB = 0x9,
    PLAINTEXTKEYBLOB = 0x8,
    PRIVATEKEYBLOB = 0x7,
    PUBLICKEYBLOB = 0x6,
    PUBLICKEYBLOBEX = 0xA,
    SIMPLEKEYBLOB = 0X1,
    SYMMETRICWRAPKEYBLOB = 0xB
}

public enum RsaMagic : uint
{
    RSA1 = 0x31415352,
    RSA2 = 0x32415352
}

public enum KeySigningAlgorithm : uint
{
    DEFAULT = 0x0,
    CALG_RSA_SIGN = 0x00002400,
    CALG_RSA_KEYX = 0x0000A400
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public readonly struct BlobHeader
{
    public readonly BlobType BlobType;
    public readonly byte Version;
    private readonly ushort Reserved;
    public readonly KeySigningAlgorithm KeySigningAlgorithm;
}

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

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public readonly struct RsaPubKeyHeader
{
    public readonly RsaMagic RsaMagic;
    public readonly uint BitLength;
    public readonly uint PublicExponent;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public readonly struct PublicKeyFileHeader
{
    public readonly KeySigningAlgorithm KeySigningAlgorithm;
    public readonly KeyHashAlgorithm KeyHashAlgorithm;
    public readonly uint PublicKeySize;
}