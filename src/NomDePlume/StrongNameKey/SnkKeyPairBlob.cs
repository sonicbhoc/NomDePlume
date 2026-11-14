using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NomDePlume.StrongNameKey;

public readonly struct SnkKeyPairBlob(ReadOnlyMemory<byte> pkBlob) : IEquatable<SnkKeyPairBlob>
{
    private const int BlobHeaderOffset = 0;
    private static readonly int RsaHeaderOffset = Unsafe.SizeOf<BlobHeader>();
    private static readonly int DataOffset = RsaHeaderOffset + Unsafe.SizeOf<RsaPubKeyHeader>();
    
    private readonly ReadOnlyMemory<byte> _pkBlob = Validate(pkBlob);
    
    public ReadOnlySpan<byte> Span => _pkBlob.Span;
    
    public bool IsEmpty => Span.Length == 0;
    public int Length => Span.Length;
    
    public byte[] ToArray() => [..Span];
    
    public ref readonly BlobHeader BlobHeader => ref MemoryMarshal.AsRef<BlobHeader>(Span[BlobHeaderOffset..]);
    public ref readonly RsaPubKeyHeader RsaPubKeyHeader => ref MemoryMarshal.AsRef<RsaPubKeyHeader>(Span[RsaHeaderOffset..]);

    private int FullLengthField => (int)(RsaPubKeyHeader.BitLength >> 3);
    private int HalfLengthField => (int)(RsaPubKeyHeader.BitLength >> 4);

    public ReadOnlySpan<byte> Modulus => Span[DataOffset..FullLengthField];
    public ReadOnlySpan<byte> Prime1 => Span[(DataOffset + FullLengthField)..HalfLengthField];
    public ReadOnlySpan<byte> Prime2 => Span[(DataOffset + FullLengthField + HalfLengthField)..HalfLengthField];
    public ReadOnlySpan<byte> Exponent1 => Span[(DataOffset + FullLengthField + HalfLengthField * 2)..HalfLengthField];
    public ReadOnlySpan<byte> Exponent2 => Span[(DataOffset + FullLengthField + HalfLengthField * 3)..HalfLengthField];
    public ReadOnlySpan<byte> Coefficient => Span[(DataOffset + FullLengthField + HalfLengthField * 4)..HalfLengthField];
    public ReadOnlySpan<byte> PrivateExponent => Span[(DataOffset + FullLengthField + HalfLengthField * 5)..FullLengthField];
    
    public bool Equals(SnkKeyPairBlob other)
    {
        return Span.SequenceEqual(other.Span);
    }

    public override bool Equals(object? other)
    {
        return other switch
        {
            SnkKeyPairBlob otherBlob => Equals(otherBlob),
            _ => false
        };
    }
    
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Span);
        return hash.ToHashCode();
    }

    private static ReadOnlyMemory<byte> Validate(ReadOnlyMemory<byte> pkBlob)
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
    
    public static bool operator ==(SnkKeyPairBlob left, SnkKeyPairBlob right) => left.Equals(right);
    public static bool operator !=(SnkKeyPairBlob left, SnkKeyPairBlob right) => !left.Equals(right);
}