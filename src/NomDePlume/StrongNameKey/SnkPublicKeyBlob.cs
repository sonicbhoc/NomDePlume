using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NomDePlume.StrongNameKey;

public readonly struct SnkPublicKeyBlob(ReadOnlyMemory<byte> pkBlob) : IEquatable<SnkPublicKeyBlob>
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

    public ReadOnlySpan<byte> Modulus => Span[DataOffset..FullLengthField];
    
    public bool Equals(SnkPublicKeyBlob other)
    {
        return Span.SequenceEqual(other.Span);
    }

    public override bool Equals(object? other)
    {
        return other switch
        {
            SnkPublicKeyBlob otherBlob => Equals(otherBlob),
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
    
    public static bool operator ==(SnkPublicKeyBlob left, SnkPublicKeyBlob right) => left.Equals(right);
    public static bool operator !=(SnkPublicKeyBlob left, SnkPublicKeyBlob right) => !left.Equals(right);
}