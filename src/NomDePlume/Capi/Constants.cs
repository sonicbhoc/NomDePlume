using System.Runtime.InteropServices;

namespace NomDePlume.Capi;

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
public struct BlobHeader
{
    public BlobType BlobType { get; internal set; }
    public byte Version { get; internal set; }
    private ushort Reserved { get; }
    public KeySigningAlgorithm KeySigningAlgorithm { get; internal set; }
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct RsaPubKeyHeader
{
    public RsaMagic RsaMagic { get; internal set; }
    public uint BitLength { get; internal set; }
    public uint PublicExponent { get; internal set; }
}