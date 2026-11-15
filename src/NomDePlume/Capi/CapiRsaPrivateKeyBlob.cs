using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NomDePlume.Capi;

public readonly struct CapiRsaPrivateKeyBlob(ReadOnlyMemory<byte> pkBlob) : IEquatable<CapiRsaPrivateKeyBlob>
{
    private const int BlobHeaderOffset = 0;
    private static readonly int RsaHeaderOffset = Unsafe.SizeOf<BlobHeader>();
    private static readonly int DataOffset = RsaHeaderOffset + Unsafe.SizeOf<RsaPubKeyHeader>();

    public CapiRsaPrivateKeyBlob(RSAParameters rsaParameters, KeySigningAlgorithm keySigningAlgorithm = KeySigningAlgorithm.CALG_RSA_SIGN) : this(FromRsaParameters(rsaParameters, keySigningAlgorithm)) { }

    internal ReadOnlyMemory<byte> PkBlob { get; } = Validate(pkBlob);

    public ReadOnlySpan<byte> AsSpan => PkBlob.Span;

    public bool IsEmpty => AsSpan.Length == 0;
    public int Length => AsSpan.Length;

    public byte[] ToArray() => [.. AsSpan];

    public ref readonly BlobHeader BlobHeader => ref MemoryMarshal.AsRef<BlobHeader>(AsSpan[BlobHeaderOffset..]);
    public ref readonly RsaPubKeyHeader RsaPubKeyHeader => ref MemoryMarshal.AsRef<RsaPubKeyHeader>(AsSpan[RsaHeaderOffset..]);

    private int FullLengthField => (int)(RsaPubKeyHeader.BitLength >> 3);
    private int HalfLengthField => (int)(RsaPubKeyHeader.BitLength >> 4);

    public ReadOnlySpan<byte> Modulus => AsSpan.Slice(DataOffset, FullLengthField);
    public ReadOnlySpan<byte> Prime1 => AsSpan.Slice(DataOffset + FullLengthField, HalfLengthField);
    public ReadOnlySpan<byte> Prime2 => AsSpan.Slice(DataOffset + FullLengthField + HalfLengthField, HalfLengthField);
    public ReadOnlySpan<byte> Exponent1 => AsSpan.Slice(DataOffset + FullLengthField + HalfLengthField * 2, HalfLengthField);
    public ReadOnlySpan<byte> Exponent2 => AsSpan.Slice(DataOffset + FullLengthField + HalfLengthField * 3, HalfLengthField);
    public ReadOnlySpan<byte> Coefficient => AsSpan.Slice(DataOffset + FullLengthField + HalfLengthField * 4, HalfLengthField);
    public ReadOnlySpan<byte> PrivateExponent => AsSpan.Slice(DataOffset + FullLengthField + HalfLengthField * 5, FullLengthField);

    public bool Equals(CapiRsaPrivateKeyBlob other)
    {
        return AsSpan.SequenceEqual(other.AsSpan);
    }

    public override bool Equals(object? other)
    {
        return other switch
        {
            CapiRsaPrivateKeyBlob otherBlob => Equals(otherBlob),
            _ => false
        };
    }

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(AsSpan);
        return hash.ToHashCode();
    }

    internal static ReadOnlyMemory<byte> Validate(ReadOnlyMemory<byte> pkBlob)
    {
        if (pkBlob.Length < DataOffset)
        {
            throw new FormatException($"Private key blob is too small; it must be at least {DataOffset} bytes long");
        }

        var span = pkBlob.Span;
        ref readonly BlobHeader header = ref MemoryMarshal.AsRef<BlobHeader>(span[BlobHeaderOffset..]);
        ref readonly RsaPubKeyHeader rsaKey = ref MemoryMarshal.AsRef<RsaPubKeyHeader>(span[RsaHeaderOffset..]);

        if (header.BlobType != BlobType.PRIVATEKEYBLOB || rsaKey.RsaMagic != RsaMagic.RSA2)
        {
            throw new FormatException($"Private key blob must be a private key type {BlobType.PRIVATEKEYBLOB}; given {header.BlobType}. Magic value must be {RsaMagic.RSA2}; given {rsaKey.RsaMagic}.");
        }

        if (rsaKey.BitLength == 0 || rsaKey.BitLength % 16 != 0)
        {
            throw new FormatException($"Private key must RSA payload length must be divisible by 16 and greater than 0. Got {rsaKey.BitLength} bytes long.");
        }

        int fullLengthField = (int)(rsaKey.BitLength >> 3);
        int halfLengthField = (int)(rsaKey.BitLength >> 4);
        int expectedLength = checked(DataOffset + (fullLengthField * 2) + (halfLengthField * 5));

        return pkBlob.Length < expectedLength
            ? throw new FormatException($"Private key blob truncated. Expected {expectedLength} bytes long, got {pkBlob.Length}.")
            : pkBlob;
    }

    public CapiRsaPublicKeyBlob GetPublicKey()
    {
        int publicBlobLength = DataOffset + Modulus.Length;
        byte[] buffer = PkBlob.Span[..publicBlobLength].ToArray();
        Span<byte> dest = buffer;

        MemoryMarshal.AsRef<BlobHeader>(dest).BlobType = BlobType.PUBLICKEYBLOB;
        MemoryMarshal.AsRef<RsaPubKeyHeader>(dest[RsaHeaderOffset..]).RsaMagic = RsaMagic.RSA1;

        return new CapiRsaPublicKeyBlob(buffer);
    }

    public RSAParameters ToRSAParameters() => new()
    {
        Modulus = RsaParameterConverter.ReverseToBigEndian(Modulus),
        Exponent = RsaParameterConverter.ConvertExponent(RsaPubKeyHeader.PublicExponent),
        P = RsaParameterConverter.ReverseToBigEndian(Prime1),
        Q = RsaParameterConverter.ReverseToBigEndian(Prime2),
        DP = RsaParameterConverter.ReverseToBigEndian(Exponent1),
        DQ = RsaParameterConverter.ReverseToBigEndian(Exponent2),
        InverseQ = RsaParameterConverter.ReverseToBigEndian(Coefficient),
        D = RsaParameterConverter.ReverseToBigEndian(PrivateExponent)
    };

    private static ReadOnlyMemory<byte> FromRsaParameters(RSAParameters rsaParameters, KeySigningAlgorithm signingAlgorithm)
    {
        if (rsaParameters.Modulus is null || rsaParameters.Exponent is null || rsaParameters.P is null || rsaParameters.Q is null || rsaParameters.DP is null || rsaParameters.DQ is null || rsaParameters.InverseQ is null || rsaParameters.D is null)
        {
            throw new FormatException("RSAParameters must include all private key values.");
        }

        int fullLength = rsaParameters.Modulus.Length;

        if (fullLength == 0 || fullLength % 2 != 0)
        {
            throw new FormatException($"Invalid RSA Modulus Length {fullLength}. (Must be a power of 2). ");
        }

        int halfLength = fullLength / 2;
        int headerSize = Unsafe.SizeOf<BlobHeader>();
        int rsaHeaderSize = Unsafe.SizeOf<RsaPubKeyHeader>();
        int dataOffset = headerSize + rsaHeaderSize;
        int totalSize = dataOffset + (fullLength * 2) + (halfLength * 5);

        byte[] blob = new byte[totalSize];
        Span<byte> buffer = blob;

        BlobHeader blobHeader = MemoryMarshal.AsRef<BlobHeader>(buffer);
        blobHeader.BlobType = BlobType.PRIVATEKEYBLOB;
        blobHeader.Version = 2;
        blobHeader.KeySigningAlgorithm = signingAlgorithm;

        RsaPubKeyHeader pubKeyHeader = MemoryMarshal.AsRef<RsaPubKeyHeader>(buffer[headerSize..]);
        pubKeyHeader.RsaMagic = RsaMagic.RSA2;
        pubKeyHeader.PublicExponent = RsaParameterConverter.ConvertExponent(rsaParameters.Exponent);
        pubKeyHeader.BitLength = (uint)(rsaParameters.Modulus.Length * 8);

        int offset = dataOffset;
        RsaParameterConverter.WriteReverseToLittleEndian(rsaParameters.Modulus, buffer.Slice(offset, fullLength));
        offset += fullLength;
        RsaParameterConverter.WriteReverseToLittleEndian(rsaParameters.P, buffer.Slice(offset, halfLength));
        offset += halfLength;
        RsaParameterConverter.WriteReverseToLittleEndian(rsaParameters.Q, buffer.Slice(offset, halfLength));
        offset += halfLength;
        RsaParameterConverter.WriteReverseToLittleEndian(rsaParameters.DP, buffer.Slice(offset, halfLength));
        offset += halfLength;
        RsaParameterConverter.WriteReverseToLittleEndian(rsaParameters.DQ, buffer.Slice(offset, halfLength));
        offset += halfLength;
        RsaParameterConverter.WriteReverseToLittleEndian(rsaParameters.InverseQ, buffer.Slice(offset, halfLength));
        offset += halfLength;
        RsaParameterConverter.WriteReverseToLittleEndian(rsaParameters.D, buffer.Slice(offset, fullLength));

        return blob;
    }

    public static bool operator ==(CapiRsaPrivateKeyBlob left, CapiRsaPrivateKeyBlob right) => left.Equals(right);
    public static bool operator !=(CapiRsaPrivateKeyBlob left, CapiRsaPrivateKeyBlob right) => !left.Equals(right);
}
