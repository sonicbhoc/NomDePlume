using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using NomDePlume.Capi;

namespace NomDePlume.StrongNamingKey;

public readonly struct SnkPublicKeyFile(ReadOnlyMemory<byte> fileBytes)
{
    private static readonly int WrapperSize = Unsafe.SizeOf<SnkPublicKeyFileHeader>();
    
    internal ReadOnlyMemory<byte> FileBytes { get; } = Validate(fileBytes);
    
    public ref readonly SnkPublicKeyFileHeader FileHeader
        => ref MemoryMarshal.AsRef<SnkPublicKeyFileHeader>(FileBytes.Span);

    public CapiRsaPublicKeyBlob PublicKey
        => new(FileBytes.Slice(WrapperSize, (checked((int)FileHeader.PublicKeySize))));

    internal static ReadOnlyMemory<byte> Validate(ReadOnlyMemory<byte> fileBytes)
    {
        if (fileBytes.Length < WrapperSize)
        {
            throw new FormatException($"Expected at least {WrapperSize} bytes; got {fileBytes.Length}.");
        }
        
        ref readonly SnkPublicKeyFileHeader header =
            ref MemoryMarshal.AsRef<SnkPublicKeyFileHeader>(fileBytes.Span);

        if (header.KeySigningAlgorithm is not (KeySigningAlgorithm.CALG_RSA_SIGN or KeySigningAlgorithm.CALG_RSA_KEYX
            or KeySigningAlgorithm.DEFAULT))
        {
            throw new FormatException($"Unexpected signature algorithm: 0x{header.KeySigningAlgorithm:X8}.");
        }

        if (header.KeyHashAlgorithm is not (KeyHashAlgorithm.CALG_SHA1 or KeyHashAlgorithm.CALG_SHA_256
            or KeyHashAlgorithm.DEFAULT))
        {
            throw new FormatException($"Unexpected key hash algorithm: 0x{header.KeyHashAlgorithm:X8}.");
        }

        int payloadLength = checked((int)header.PublicKeySize);
        int fileLength = checked(WrapperSize + payloadLength);

        if (fileBytes.Length < fileLength)
        {
            throw new FormatException(
                $"Public key file is truncated. Expected at least {fileLength}; got {fileBytes.Length}.");
        }
        
        CapiRsaPublicKeyBlob pk = new(fileBytes.Slice(WrapperSize, payloadLength));

        if (pk.BlobHeader.KeySigningAlgorithm != header.KeySigningAlgorithm)
        {
            throw new FormatException(
                $"Key signing algorithm mismatch: File Header: {header.KeySigningAlgorithm:X8}; PK Data Header: {pk.BlobHeader.KeySigningAlgorithm:X8}.");
        }

        return fileBytes;
    }
}