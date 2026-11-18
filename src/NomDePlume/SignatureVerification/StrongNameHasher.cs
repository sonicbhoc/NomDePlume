using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using NomDePlume.StrongNamingKey;

namespace NomDePlume.SignatureVerification;

public sealed class StrongNameHasher : IStrongNameHasher
{
    private const int ChecksumOffsetInOptionalHeader = 64;
    private const int Pe32DataDirectoriesOffset = 96;
    private const int Pe32PlusDataDirectoriesOffset = 112;
    private const int SecurityDirectoryIndex = 4;
    private const int DataDirectoryEntrySize = 8;

    public StrongNameHashComputationResult ComputePeStrongNameHash(PEReader peReader)
    {
        ArgumentNullException.ThrowIfNull(peReader);

        if (!peReader.HasMetadata)
        {
            throw new BadImageFormatException("The image does not contain assembly metadata.");
        }

        MetadataReader metadataReader = peReader.GetMetadataReader();
        if (!metadataReader.IsAssembly)
        {
            throw new BadImageFormatException("The image does not contain an assembly.");
        }

        AssemblyDefinition assembly = metadataReader.GetAssemblyDefinition();
        byte[] publicKeyBytes = metadataReader.GetBlobBytes(assembly.PublicKey);
        if (publicKeyBytes.Length == 0)
        {
            throw new BadImageFormatException("The assembly does not contain a strong-name public key.");
        }

        SnkPublicKeyFile publicKey = new(publicKeyBytes);
        HashAlgorithmName hashAlgorithm = publicKey.FileHeader.KeyHashAlgorithm switch
        {
            KeyHashAlgorithm.DEFAULT or KeyHashAlgorithm.CALG_SHA1 => HashAlgorithmName.SHA1,
            KeyHashAlgorithm.CALG_SHA_256 => HashAlgorithmName.SHA256,
            _ => throw new FormatException(
                $"Unsupported strong-name hash algorithm: {publicKey.FileHeader.KeyHashAlgorithm}.")
        };

        CorHeader corHeader = peReader.PEHeaders.CorHeader
            ?? throw new BadImageFormatException("The image does not contain a COR header.");
        DirectoryEntry signatureDirectory = corHeader.StrongNameSignatureDirectory;
        if (signatureDirectory.Size <= 0
            || !peReader.PEHeaders.TryGetDirectoryOffset(signatureDirectory, out int signatureOffset))
        {
            throw new BadImageFormatException("The image does not contain a valid strong-name signature directory.");
        }

        byte[] image = peReader.GetEntireImage().GetContent().ToArray();
        int signatureLength = checked((int)signatureDirectory.Size);
        if (signatureOffset < 0 || signatureLength > image.Length - signatureOffset)
        {
            throw new BadImageFormatException("The strong-name signature directory is outside the PE image.");
        }

        byte[] hash = ComputeHash(image, peReader.PEHeaders, signatureDirectory, hashAlgorithm);
        return new StrongNameHashComputationResult(
            new StrongNameHashData(hash, hashAlgorithm, signatureOffset, signatureLength));
    }

    public static byte[] ComputeHash(
        ReadOnlyMemory<byte> image,
        PEHeaders headers,
        DirectoryEntry strongNameSignatureDirectory,
        HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm.Name);

        PEHeader peHeader = headers.PEHeader
            ?? throw new BadImageFormatException("The image does not contain a PE header.");
        int optionalHeaderOffset = checked(headers.CoffHeaderStartOffset + 20);
        int unalignedHeaderSize = checked(
            optionalHeaderOffset
            + headers.CoffHeader.SizeOfOptionalHeader
            + headers.CoffHeader.NumberOfSections * 40);
        int alignedHeaderSize = checked((int)peHeader.SizeOfHeaders);
        var hashRanges = new List<(int Offset, int Length, bool Zero)>
        {
            (checked(optionalHeaderOffset + ChecksumOffsetInOptionalHeader), sizeof(uint), true)
        };

        if (alignedHeaderSize < unalignedHeaderSize)
        {
            throw new BadImageFormatException("The PE headers extend beyond the declared headers size.");
        }

        if (alignedHeaderSize > unalignedHeaderSize)
        {
            hashRanges.Add((unalignedHeaderSize, alignedHeaderSize - unalignedHeaderSize, false));
        }

        if (peHeader.NumberOfRvaAndSizes > SecurityDirectoryIndex)
        {
            int dataDirectoriesOffset = peHeader.Magic == PEMagic.PE32
                ? Pe32DataDirectoriesOffset
                : Pe32PlusDataDirectoriesOffset;
            int securityDirectoryOffset = checked(
                optionalHeaderOffset + dataDirectoriesOffset + SecurityDirectoryIndex * DataDirectoryEntrySize);
            hashRanges.Add((securityDirectoryOffset, DataDirectoryEntrySize, true));
        }

        if (strongNameSignatureDirectory.Size > 0)
        {
            if (!headers.TryGetDirectoryOffset(strongNameSignatureDirectory, out int signatureOffset))
            {
                throw new BadImageFormatException("The strong-name signature directory is outside the PE image.");
            }

            hashRanges.Add((signatureOffset, checked((int)strongNameSignatureDirectory.Size), false));
        }

        hashRanges.Sort(static (left, right) => left.Offset.CompareTo(right.Offset));

        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);
        ReadOnlySpan<byte> imageSpan = image.Span;
        Span<byte> zeroBytes = stackalloc byte[DataDirectoryEntrySize];
        zeroBytes.Clear();
        int position = 0;

        foreach ((int offset, int length, bool zero) in hashRanges)
        {
            int end = checked(offset + length);
            if (offset < position || end > imageSpan.Length)
            {
                throw new BadImageFormatException("A PE hash range is outside the image.");
            }

            if (offset > position)
            {
                hash.AppendData(imageSpan[position..offset]);
            }

            if (zero)
            {
                hash.AppendData(zeroBytes[..length]);
            }

            position = Math.Max(position, end);
        }

        if (position < imageSpan.Length)
        {
            hash.AppendData(imageSpan[position..]);
        }

        return hash.GetHashAndReset();
    }
}
