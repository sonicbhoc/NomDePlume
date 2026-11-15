using static System.Buffers.Binary.BinaryPrimitives;

namespace NomDePlume.Capi;

public static class RsaParameterConverter
{
    public static byte[] ReverseToBigEndian(ReadOnlySpan<byte> littleEndianBytes)
    {
        byte[] reversedBytes = [.. littleEndianBytes];
        Array.Reverse(reversedBytes);
        return reversedBytes;
    }

    public static void WriteReverseToLittleEndian(ReadOnlySpan<byte> bigEndianBytes, Span<byte> littleEndianBuffer)
    {
        if (bigEndianBytes.Length > littleEndianBuffer.Length)
        {
            throw new InvalidOperationException("BigEndian buffer is larger than little endian.");
        }

        int padBytes = littleEndianBuffer.Length - bigEndianBytes.Length;
        bigEndianBytes.CopyTo(littleEndianBuffer[padBytes..]);
        littleEndianBuffer.Reverse();
    }

    public static byte[] ConvertExponent(uint pubExp)
    {
        Span<byte> buffer = stackalloc byte[4];
        WriteUInt32BigEndian(buffer, pubExp);

        // Strip leading 0s
        int firstNonZeroIndex = buffer.IndexOfAnyExcept((byte)0);
        return firstNonZeroIndex < 0 ? [0] : [.. buffer[firstNonZeroIndex..]];
    }

    public static uint ConvertExponent(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length is 0 or > 4)
        {
            throw new ArgumentOutOfRangeException(nameof(buffer), "RSA exponent must be between 1 and 4 bytes.");
        }

        Span<byte> padded = stackalloc byte[4];
        buffer.CopyTo(padded[(4 - buffer.Length)..]);

        return ReadUInt32BigEndian(padded);
    }
}
