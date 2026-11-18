using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using NomDePlume.StrongNamingKey;

namespace NomDePlume.StrongNaming;

public sealed class StrongNameSignatureVerifier(IStrongNameVerificationSkipList skipList)
    : IStrongNameSignatureVerifier
{
    public async Task<StrongNameSignatureVerificationResult> VerifyAssemblyStrongNamingAsync(
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

        try
        {
            using var stream = new MemoryStream(image, writable: false);
            using var peReader = new PEReader(stream, PEStreamOptions.PrefetchEntireImage);
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

            string assemblyName = metadataReader.GetString(assembly.Name);
            if (!force)
            {
                string tokenString;
                try
                {
                    tokenString = Convert.ToHexString(SnkFile.Parse(publicKeyBytes).GetPublicKeyToken().ToArray());
                }
                catch (FormatException exception)
                {
                    return new StrongNameHasherError(
                        new InvalidStrongNamePublicKey(assemblyPath, exception.Message));
                }
                catch (ArgumentOutOfRangeException exception)
                {
                    return new StrongNameHasherError(
                        new InvalidStrongNamePublicKey(assemblyPath, exception.Message));
                }

                if (skipList.IsVerificationSkipped(assemblyPath, assemblyName, tokenString))
                {
                    return new StrongNameVerificationSkipped(assemblyPath);
                }
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
                StrongNameHasher.ComputePeStrongNameHash(peReader, assemblyPath);
            if (hashResult.TryGetValue(out StrongNameHasherError hashingError))
            {
                return hashingError;
            }

            if (!hashResult.TryGetValue(out StrongNameHashData hashData))
            {
                throw new InvalidOperationException("The strong-name hasher returned an empty result.");
            }

            SnkPublicKeyFile publicKey;
            try
            {
                publicKey = new SnkPublicKeyFile(publicKeyBytes);
            }
            catch (FormatException exception)
            {
                return new StrongNameHasherError(
                    new InvalidStrongNamePublicKey(assemblyPath, exception.Message));
            }
            catch (ArgumentOutOfRangeException exception)
            {
                return new StrongNameHasherError(
                    new InvalidStrongNamePublicKey(assemblyPath, exception.Message));
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
        catch (OverflowException exception)
        {
            return new StrongNameHasherError(new InvalidStrongNameImage(assemblyPath, exception.Message));
        }
        catch (CryptographicException)
        {
            return new StrongNameSignatureInvalid(assemblyPath);
        }
    }
}
