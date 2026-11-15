using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using NomDePlume.Capi;

namespace NomDePlume.StrongNamingKey;

public union SnkFile(SnkPublicKeyFile, CapiRsaPrivateKeyBlob)
{
    public bool HasPrivateKey => this is CapiRsaPrivateKeyBlob;

    public uint BitLength => this switch
    {
        SnkPublicKeyFile pub => pub.PublicKey.RsaPubKeyHeader.BitLength,
        CapiRsaPrivateKeyBlob pk => pk.RsaPubKeyHeader.BitLength
    };

    public uint PublicExponent => this switch
    {
        SnkPublicKeyFile pub => pub.PublicKey.RsaPubKeyHeader.PublicExponent,
        CapiRsaPrivateKeyBlob pk => pk.RsaPubKeyHeader.PublicExponent
    };

    public ReadOnlySpan<byte> Modulus => this switch
    {
        SnkPublicKeyFile pub => pub.PublicKey.Modulus,
        CapiRsaPrivateKeyBlob pk => pk.Modulus
    };

    public static SnkFile Parse(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            throw new ArgumentException("SNK File buffer cannot be empty.");
        }

        /*
         * Determine contents of SNK file. Public keys are wrapped in a 12-byte ECMA header, so the first byte of the
         * file corresponds to the first byte of the ECMA header, not the first byte of the actual key header.
         * That first byte is `0x00` if the header contains only valid data.
         */
        return bytes.Span[0] switch
        {
            (int)BlobType.PRIVATEKEYBLOB => new CapiRsaPrivateKeyBlob(bytes),
            0x00 => new SnkPublicKeyFile(bytes),
            var blobType => throw new FormatException($"File contains unknown blob data type {blobType}.")
        };
    }

    public ReadOnlyMemory<byte> ToEcmaPublicKeyBytes() => this switch
    {
        SnkPublicKeyFile pub => pub.FileBytes,
        CapiRsaPrivateKeyBlob pk => CapiPrivateKeyToPublicKeyFile(pk)
    };

    private static ReadOnlyMemory<byte> CapiPrivateKeyToPublicKeyFile(CapiRsaPrivateKeyBlob privateKeyBlob)
    {
        var pubKey = privateKeyBlob.GetPublicKey();
        byte[] headerBytes = new byte[Unsafe.SizeOf<SnkPublicKeyFileHeader>()];
        SnkPublicKeyFileHeader header = MemoryMarshal.AsRef<SnkPublicKeyFileHeader>(headerBytes);
        header.KeySigningAlgorithm = pubKey.BlobHeader.KeySigningAlgorithm;
        header.PublicKeySize = (uint)pubKey.Length;
        header.KeyHashAlgorithm = KeyHashAlgorithm.CALG_SHA1;

        byte[] fileBytes = [.. pubKey.Span.ToArray(), .. headerBytes];

        return fileBytes.AsMemory();
    }
}
