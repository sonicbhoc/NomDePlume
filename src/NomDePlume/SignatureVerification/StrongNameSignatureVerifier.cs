using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;

using NomDePlume.StrongNamingKey;

namespace NomDePlume.SignatureVerification;

public sealed class StrongNameSignatureVerifier(
    IStrongNameVerificationSkipList skipList,
    IStrongNameHasher hasher)
    : IStrongNameSignatureVerifier
{
    public async Task<SignatureVerificationResult> VerifyAssemblyStrongNamingAsync(
        FilePath assemblyPath,
        bool force = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(assemblyPath.Value);

        byte[] image;
        try
        {
            image = await File.ReadAllBytesAsync(assemblyPath.Value).ConfigureAwait(false);
        }
        catch (FileNotFoundException)
        {
            return new AssemblyFileNotFound(assemblyPath);
        }
        catch (DirectoryNotFoundException)
        {
            return new AssemblyFileNotFound(assemblyPath);
        }

        using var stream = new MemoryStream(image, writable: false);
        using var peReader = new PEReader(stream);
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
                return new StrongNameHasherError(new CorHeaderNotFound(assemblyPath));
            }

            if ((corHeader.Flags & CorFlags.StrongNameSigned) == 0)
            {
                return new CorStrongNameFlagUnset(assemblyPath);
            }

            StrongNameHashComputationResult hashResult =
                hasher.ComputePeStrongNameHash(peReader, assemblyPath);
            if (hashResult.TryGetValue(out StrongNameHasherError hashingError))
            {
                return hashingError;
            }

            if (!hashResult.TryGetValue(out StrongNameHashData hashData))
            {
                throw new InvalidOperationException("The strong-name hasher returned an empty result.");
            }

            byte[] signature = image.AsSpan(hashData.SignatureOffset, hashData.SignatureLength).ToArray();
            Array.Reverse(signature);

            using RSA rsa = RSA.Create();
            rsa.ImportParameters(publicKey.ToRSAParameters());
            return rsa.VerifyHash(hashData.Hash, signature, hashData.AlgorithmName, RSASignaturePadding.Pkcs1)
                ? new StrongNameSignatureValid(assemblyPath)
                : new StrongNameSignatureInvalid(assemblyPath);
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
        catch (CryptographicException)
        {
            return new StrongNameSignatureInvalid(assemblyPath);
        }
    }
}
