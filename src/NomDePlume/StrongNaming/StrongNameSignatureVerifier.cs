using System.Reflection.PortableExecutable;
using System.Reflection.Metadata;
using System.Security.Cryptography;
using NomDePlume.StrongNamingKey;

namespace NomDePlume.StrongNaming;

public sealed class StrongNameSignatureVerifier
{
    private readonly IStrongNameVerificationSkipList skipList;

    public StrongNameSignatureVerifier(IStrongNameVerificationSkipList? skipList = null)
    {
        this.skipList = skipList ?? new WindowsRegistryStrongNameVerificationSkipList();
    }

    public StrongNameSignatureVerificationResult Verify(string assemblyPath, bool force = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(assemblyPath);

        using FileStream stream = File.OpenRead(assemblyPath);
        using var peReader = new PEReader(stream, PEStreamOptions.PrefetchEntireImage);
        if (!peReader.HasMetadata)
        {
            return StrongNameSignatureVerificationResult.Invalid;
        }

        MetadataReader metadataReader = peReader.GetMetadataReader();
        if (!metadataReader.IsAssembly)
        {
            return StrongNameSignatureVerificationResult.Invalid;
        }

        AssemblyDefinition assembly = metadataReader.GetAssemblyDefinition();
        byte[] publicKeyBytes = metadataReader.GetBlobBytes(assembly.PublicKey);
        if (publicKeyBytes.Length == 0)
        {
            return StrongNameSignatureVerificationResult.Invalid;
        }

        var publicKeyFile = new SnkPublicKeyFile(publicKeyBytes);
        byte[] publicKeyToken = SnkFile.Parse(publicKeyBytes).GetPublicKeyToken().ToArray();
        string tokenString = Convert.ToHexString(publicKeyToken);
        string assemblyName = metadataReader.GetString(assembly.Name);

        if (!force && skipList.IsVerificationSkipped(assemblyPath, assemblyName, tokenString))
        {
            return StrongNameSignatureVerificationResult.Skipped;
        }

        CorHeader? corHeader = peReader.PEHeaders.CorHeader;
        if (corHeader is null
            || (corHeader.Flags & CorFlags.StrongNameSigned) == 0
            || corHeader.StrongNameSignatureDirectory.Size == 0
            || !peReader.PEHeaders.TryGetDirectoryOffset(corHeader.StrongNameSignatureDirectory, out int signatureOffset))
        {
            return StrongNameSignatureVerificationResult.Invalid;
        }

        byte[] image = peReader.GetEntireImage().GetContent().ToArray();
        int signatureSize = checked((int)corHeader.StrongNameSignatureDirectory.Size);
        if (signatureOffset < 0 || signatureSize > image.Length - signatureOffset)
        {
            throw new BadImageFormatException("The strong-name signature directory is outside the PE image.");
        }

        HashAlgorithmName hashAlgorithm = publicKeyFile.FileHeader.KeyHashAlgorithm switch
        {
            KeyHashAlgorithm.DEFAULT or KeyHashAlgorithm.CALG_SHA1 => HashAlgorithmName.SHA1,
            KeyHashAlgorithm.CALG_SHA_256 => HashAlgorithmName.SHA256,
            _ => throw new FormatException(
                $"Unsupported strong-name hash algorithm: {publicKeyFile.FileHeader.KeyHashAlgorithm}.")
        };

        byte[] hash = StrongNameHasher.ComputeHash(
            image,
            peReader.PEHeaders,
            corHeader.StrongNameSignatureDirectory,
            hashAlgorithm);
        byte[] signature = image.AsSpan(signatureOffset, signatureSize).ToArray();
        Array.Reverse(signature);

        using RSA rsa = RSA.Create();
        rsa.ImportParameters(publicKeyFile.ToRSAParameters());
        return rsa.VerifyHash(hash, signature, hashAlgorithm, RSASignaturePadding.Pkcs1)
            ? StrongNameSignatureVerificationResult.Valid
            : StrongNameSignatureVerificationResult.Invalid;
    }
}
