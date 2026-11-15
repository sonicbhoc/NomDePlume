using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NomDePlume.Capi;

public readonly struct CapiRsaPublicKeyBlob(ReadOnlyMemory<byte> pkBlob) : IEquatable<CapiRsaPublicKeyBlob>
{
    private const int BlobHeaderOffset = 0;
    private static readonly int RsaHeaderOffset = Unsafe.SizeOf<BlobHeader>();
    private static readonly int DataOffset = RsaHeaderOffset + Unsafe.SizeOf<RsaPubKeyHeader>();

    public CapiRsaPublicKeyBlob(RSAParameters rsaParameters, KeySigningAlgorithm keySigningAlgorithm = KeySigningAlgorithm.CALG_RSA_SIGN) : this(FromRsaParameters(rsaParameters, keySigningAlgorithm)) { }
    internal ReadOnlyMemory<byte> PkBlob { get; } = Validate(pkBlob);

    public ReadOnlySpan<byte> Span => PkBlob.Span;

    public bool IsEmpty => Span.Length == 0;
    public int Length => Span.Length;

    public byte[] ToArray() => [.. Span];

    public ref readonly BlobHeader BlobHeader => ref MemoryMarshal.AsRef<BlobHeader>(Span[BlobHeaderOffset..]);
    public ref readonly RsaPubKeyHeader RsaPubKeyHeader => ref MemoryMarshal.AsRef<RsaPubKeyHeader>(Span[RsaHeaderOffset..]);

    private int FullLengthField => (int)(RsaPubKeyHeader.BitLength >> 3);

    public ReadOnlySpan<byte> Modulus => Span.Slice(DataOffset, FullLengthField);

    public bool Equals(CapiRsaPublicKeyBlob other)
    {
        return Span.SequenceEqual(other.Span);
    }

    public override bool Equals(object? other)
    {
        return other switch
        {
            CapiRsaPublicKeyBlob otherBlob => Equals(otherBlob),
            _ => false
        };
    }

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Span);
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

        if (header.BlobType != BlobType.PUBLICKEYBLOB || rsaKey.RsaMagic != RsaMagic.RSA1)
        {
            throw new FormatException($"Private key blob must be a private key type {BlobType.PUBLICKEYBLOB}; given {header.BlobType}. Magic value must be {RsaMagic.RSA2}; given {rsaKey.RsaMagic}.");
        }

        if (rsaKey.BitLength == 0 || rsaKey.BitLength % 16 != 0)
        {
            throw new FormatException($"Private key must RSA payload length must be divisible by 16 and greater than 0. Got {rsaKey.BitLength} bytes long.");
        }

        int fullLengthField = (int)(rsaKey.BitLength >> 3);
        int expectedLength = checked(DataOffset + fullLengthField);

        return pkBlob.Length < expectedLength
            ? throw new FormatException($"Private key blob truncated. Expected {expectedLength} bytes long, got {pkBlob.Length}.")
            : pkBlob;
    }

    public RSAParameters ToRSAParameters() => new()
    {
        Modulus = RsaParameterConverter.ReverseToBigEndian(Modulus),
        Exponent = RsaParameterConverter.ConvertExponent(RsaPubKeyHeader.PublicExponent),
    };

    private static ReadOnlyMemory<byte> FromRsaParameters(RSAParameters rsaParameters,
        KeySigningAlgorithm keySigningAlgorithm)
    {
        if (rsaParameters.Modulus is null || rsaParameters.Exponent is null)
        {
            throw new FormatException("RSA parameters must include the Modulus and Exponent.");
        }

        int fullLengthField = rsaParameters.Modulus.Length;

        if (fullLengthField is 0 || fullLengthField % 2 is not 0)
        {
            throw new FormatException($"Invalid RSA modulus length {fullLengthField}. Must be divisible by 2.");
        }

        int headerSize = Unsafe.SizeOf<BlobHeader>();
        int rsaHeaderSize = Unsafe.SizeOf<RsaPubKeyHeader>();
        int dataOffset = headerSize + rsaHeaderSize;
        int totalSize = dataOffset + fullLengthField;

        byte[] blob = new byte[totalSize];
        Span<byte> buffer = blob;

        BlobHeader header = MemoryMarshal.AsRef<BlobHeader>(buffer);
        header.KeySigningAlgorithm = keySigningAlgorithm;
        header.Version = 2;
        header.BlobType = BlobType.PUBLICKEYBLOB;

        RsaPubKeyHeader pubKeyHeader = MemoryMarshal.AsRef<RsaPubKeyHeader>(buffer[headerSize..]);
        pubKeyHeader.BitLength = (uint)(rsaParameters.Modulus.Length * 8);
        pubKeyHeader.PublicExponent = RsaParameterConverter.ConvertExponent(rsaParameters.Exponent);
        pubKeyHeader.RsaMagic = RsaMagic.RSA1;

        RsaParameterConverter.WriteReverseToLittleEndian(buffer[dataOffset..], rsaParameters.Modulus);

        return blob;
    }

    public static bool operator ==(CapiRsaPublicKeyBlob left, CapiRsaPublicKeyBlob right) => left.Equals(right);
    public static bool operator !=(CapiRsaPublicKeyBlob left, CapiRsaPublicKeyBlob right) => !left.Equals(right);
}
