using DotMake.CommandLine;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using NomDePlume.StrongNamingKey;

namespace NomDePlume.SignatureVerification;

public sealed class StrongNameSignatureVerifier : IStrongNameSignatureVerifier
{
    private readonly IStrongNameVerificationSkipList skipList;
    private readonly IStrongNameHasher hasher;

    public StrongNameSignatureVerifier(
        IStrongNameVerificationSkipList? skipList = null,
        IStrongNameHasher? hasher = null)
    {
        this.skipList = skipList ?? new WindowsRegistryStrongNameVerificationSkipList();
        this.hasher = hasher ?? new StrongNameHasher();
    }

    public SignatureVerificationResult VerifyAssemblyStrongNaming(FilePath assemblyPath, bool force = false)
        => Verify(assemblyPath.Value, force);

    public SignatureVerificationResult Verify(string assemblyPath, bool force = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(assemblyPath);
        if (!File.Exists(assemblyPath))
        {
            return new AssemblyFileNotFound(assemblyPath);
        }

        using FileStream stream = File.OpenRead(assemblyPath);
        using var peReader = new PEReader(stream, PEStreamOptions.PrefetchEntireImage);
        if (!peReader.HasMetadata)
        {
            return new PEHeaderEmpty(assemblyPath);
        }

        MetadataReader metadataReader = peReader.GetMetadataReader();
        if (!metadataReader.IsAssembly)
        {
            return new NotAnAssembly(assemblyPath);
        }

        AssemblyDefinition assembly = metadataReader.GetAssemblyDefinition();
        byte[] publicKeyBytes = metadataReader.GetBlobBytes(assembly.PublicKey);
        if (publicKeyBytes.Length == 0)
        {
            return new StrongNameSignatureInvalid(assemblyPath);
        }

        SnkPublicKeyFile publicKey = new(publicKeyBytes);
        string tokenString = Convert.ToHexString(SnkFile.Parse(publicKeyBytes).GetPublicKeyToken().ToArray());
        string assemblyName = metadataReader.GetString(assembly.Name);
        if (!force && skipList.IsVerificationSkipped(assemblyPath, assemblyName, tokenString))
        {
            return new StrongNameVerificationSkipped(assemblyPath);
        }

        CorHeader? corHeader = peReader.PEHeaders.CorHeader;
        if (corHeader is null)
        {
            return new CorHeaderNotFound(assemblyPath);
        }

        if ((corHeader.Flags & CorFlags.StrongNameSigned) == 0)
        {
            return new CorStrongNameFlagUnset(assemblyPath);
        }

        StrongNameHashData hashData = hasher.ComputePeStrongNameHash(peReader).Data;
        byte[] image = peReader.GetEntireImage().GetContent().ToArray();
        byte[] signature = image.AsSpan(hashData.SignatureOffset, hashData.SignatureLength).ToArray();
        Array.Reverse(signature);

        using RSA rsa = RSA.Create();
        rsa.ImportParameters(publicKey.ToRSAParameters());
        return rsa.VerifyHash(hashData.Hash, signature, hashData.AlgorithmName, RSASignaturePadding.Pkcs1)
            ? new StrongNameSignatureValid(assemblyPath)
            : new StrongNameSignatureInvalid(assemblyPath);
    }
}
