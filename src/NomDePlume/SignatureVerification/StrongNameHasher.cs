using System.Buffers.Binary;
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

    public unsafe StrongNameHashComputationResult ComputePeStrongNameHash(
        PEReader peReader,
        FilePath assemblyPath)
    {
        ArgumentNullException.ThrowIfNull(peReader);

        try
        {
            if (!peReader.HasMetadata)
            {
                return new StrongNameHasherError(new PEHeaderEmpty(assemblyPath));
            }

            MetadataReader metadataReader = peReader.GetMetadataReader();
            if (!metadataReader.IsAssembly)
            {
                return new StrongNameHasherError(new NotAnAssembly(assemblyPath));
            }

            AssemblyDefinition assembly = metadataReader.GetAssemblyDefinition();
            byte[] publicKeyBytes = metadataReader.GetBlobBytes(assembly.PublicKey);
            if (publicKeyBytes.Length == 0)
            {
                return new StrongNameHasherError(new StrongNamePublicKeyMissing(assemblyPath));
            }

            if (publicKeyBytes.Length < sizeof(uint) * 3)
            {
                return new StrongNameHasherError(new InvalidStrongNamePublicKey(
                    assemblyPath,
                    $"Expected at least {sizeof(uint) * 3} bytes; got {publicKeyBytes.Length}."));
            }

            KeyHashAlgorithm keyHashAlgorithm = (KeyHashAlgorithm)BinaryPrimitives.ReadUInt32LittleEndian(
                publicKeyBytes.AsSpan(sizeof(uint)));
            HashAlgorithmName hashAlgorithm = keyHashAlgorithm switch
            {
                KeyHashAlgorithm.DEFAULT or KeyHashAlgorithm.CALG_SHA1 => HashAlgorithmName.SHA1,
                KeyHashAlgorithm.CALG_SHA_256 => HashAlgorithmName.SHA256,
                _ => default
            };
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
            {
                return new StrongNameHasherError(new UnsupportedStrongNameHashAlgorithm(
                    assemblyPath,
                    $"Unsupported strong-name hash algorithm: {keyHashAlgorithm}."));
            }

            CorHeader? corHeader = peReader.PEHeaders.CorHeader;
            if (corHeader is null)
            {
                return new StrongNameHasherError(new CorHeaderNotFound(assemblyPath));
            }

            DirectoryEntry signatureDirectory = corHeader.StrongNameSignatureDirectory;
            if (signatureDirectory.Size <= 0
                || !peReader.PEHeaders.TryGetDirectoryOffset(signatureDirectory, out int signatureOffset))
            {
                return new StrongNameHasherError(new InvalidStrongNameSignatureDirectory(
                    assemblyPath,
                    "The image does not contain a valid strong-name signature directory."));
            }

            if (!peReader.IsEntireImageAvailable)
            {
                return new StrongNameHasherError(new InvalidStrongNameImage(
                    assemblyPath,
                    "The entire PE image is not available for strong-name hashing."));
            }

            BlobReader imageReader = peReader.GetEntireImage().GetReader();
            ReadOnlySpan<byte> image = new(imageReader.CurrentPointer, imageReader.Length);
            int signatureLength = signatureDirectory.Size;
            if (signatureOffset < 0 || signatureLength > image.Length - signatureOffset)
            {
                return new StrongNameHasherError(new InvalidStrongNameSignatureDirectory(
                    assemblyPath,
                    "The strong-name signature directory is outside the PE image."));
            }

            StrongNameHashComputationResult result =
                ComputeHash(image, peReader.PEHeaders, signatureDirectory, hashAlgorithm, assemblyPath);
            GC.KeepAlive(peReader); // The span points into memory owned by the PEReader.
            return result;
        }
        catch (BadImageFormatException exception)
        {
            return new StrongNameHasherError(new InvalidStrongNameImage(assemblyPath, exception.Message));
        }
        catch (FormatException exception)
        {
            return new StrongNameHasherError(new InvalidStrongNamePublicKey(assemblyPath, exception.Message));
        }
        catch (OverflowException exception)
        {
            return new StrongNameHasherError(new InvalidStrongNameImage(assemblyPath, exception.Message));
        }
        catch (ArgumentOutOfRangeException exception)
        {
            return new StrongNameHasherError(new InvalidStrongNamePublicKey(assemblyPath, exception.Message));
        }
    }

    internal static StrongNameHashComputationResult ComputeHash(
        ReadOnlySpan<byte> image,
        PEHeaders headers,
        DirectoryEntry strongNameSignatureDirectory,
        HashAlgorithmName hashAlgorithm,
        FilePath assemblyPath)
    {
        ArgumentNullException.ThrowIfNull(headers);
        string algorithmName = hashAlgorithm.Name ?? string.Empty;
        if (algorithmName.Length == 0)
        {
            return new StrongNameHasherError(
                new UnsupportedStrongNameHashAlgorithm(assemblyPath, algorithmName));
        }

        if (strongNameSignatureDirectory.Size < 0)
        {
            return new StrongNameHasherError(new InvalidStrongNameSignatureDirectory(
                assemblyPath,
                "The strong-name signature directory has a negative size."));
        }

        try
        {
            PEHeader? peHeader = headers.PEHeader;
            if (peHeader is null)
            {
                return new StrongNameHasherError(
                    new InvalidStrongNameImage(assemblyPath, "The image does not contain a PE header."));
            }

            int optionalHeaderOffset = checked(headers.CoffHeaderStartOffset + 20);
            int unalignedHeaderSize = checked(
                optionalHeaderOffset
                + headers.CoffHeader.SizeOfOptionalHeader
                + headers.CoffHeader.NumberOfSections * 40);
            int alignedHeaderSize = peHeader.SizeOfHeaders;
            var hashRanges = new List<(int Offset, int Length, bool Zero)>
            {
                (checked(optionalHeaderOffset + ChecksumOffsetInOptionalHeader), sizeof(uint), true)
            };

            if (alignedHeaderSize < unalignedHeaderSize)
            {
                return new StrongNameHasherError(new InvalidStrongNameImage(
                    assemblyPath,
                    "The PE headers extend beyond the declared headers size."));
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
                    optionalHeaderOffset
                    + dataDirectoriesOffset
                    + SecurityDirectoryIndex * DataDirectoryEntrySize);
                hashRanges.Add((securityDirectoryOffset, DataDirectoryEntrySize, true));
            }

            int signatureOffset = 0;
            if (strongNameSignatureDirectory.Size > 0)
            {
                if (!headers.TryGetDirectoryOffset(strongNameSignatureDirectory, out signatureOffset))
                {
                    return new StrongNameHasherError(new InvalidStrongNameSignatureDirectory(
                        assemblyPath,
                        "The strong-name signature directory is outside the PE image."));
                }

                hashRanges.Add((signatureOffset, strongNameSignatureDirectory.Size, false));
            }

            hashRanges.Sort(static (left, right) => left.Offset.CompareTo(right.Offset));

            using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);
            Span<byte> zeroBytes = stackalloc byte[DataDirectoryEntrySize];
            zeroBytes.Clear();
            int position = 0;

            foreach ((int offset, int length, bool zero) in hashRanges)
            {
                int end = checked(offset + length);
                if (offset < position || end > image.Length)
                {
                    return new StrongNameHasherError(new InvalidStrongNameImage(
                        assemblyPath,
                        "A PE hash range is outside the image."));
                }

                if (offset > position)
                {
                    hash.AppendData(image[position..offset]);
                }

                if (zero)
                {
                    hash.AppendData(zeroBytes[..length]);
                }

                position = Math.Max(position, end);
            }

            if (position < image.Length)
            {
                hash.AppendData(image[position..]);
            }

            return new StrongNameHashData(
                hash.GetHashAndReset(),
                hashAlgorithm,
                signatureOffset,
                strongNameSignatureDirectory.Size);
        }
        catch (OverflowException exception)
        {
            return new StrongNameHasherError(new InvalidStrongNameImage(assemblyPath, exception.Message));
        }
        catch (CryptographicException)
        {
            return new StrongNameHasherError(
                new UnsupportedStrongNameHashAlgorithm(assemblyPath, algorithmName));
        }
    }
}
