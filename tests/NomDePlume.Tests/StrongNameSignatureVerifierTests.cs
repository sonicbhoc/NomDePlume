using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NomDePlume.Capi;
using NomDePlume.Commands;
using NomDePlume.StrongNaming;
using NomDePlume.StrongNamingKey;

namespace NomDePlume.Tests;

[TestClass]
public sealed class StrongNameSignatureVerifierTests
{
    [TestMethod]
    public void Verify_SignedAssembly_ReturnsValid()
    {
        (string signedAssembly, byte[] signingHash) = CreateSignedAssembly();

        try
        {
            byte[] image = File.ReadAllBytes(signedAssembly);
            using var peReader = new PEReader(new MemoryStream(image));
            byte[] computedHash = StrongNameHasher.ComputeHash(
                image,
                peReader.PEHeaders,
                peReader.PEHeaders.CorHeader!.StrongNameSignatureDirectory,
                HashAlgorithmName.SHA1);
            CollectionAssert.AreEqual(signingHash, computedHash);

            var verifier = new StrongNameSignatureVerifier();

            Assert.AreEqual(StrongNameSignatureVerificationResult.Valid, verifier.Verify(signedAssembly));
        }
        finally
        {
            File.Delete(signedAssembly);
        }
    }

    [TestMethod]
    public void Verify_Sha256SignedAssembly_ReturnsValid()
    {
        var (signedAssembly, _) = CreateSignedAssembly(HashAlgorithmName.SHA256);

        try
        {
            var verifier = new StrongNameSignatureVerifier();

            Assert.AreEqual(StrongNameSignatureVerificationResult.Valid, verifier.Verify(signedAssembly));
        }
        finally
        {
            File.Delete(signedAssembly);
        }
    }

    [TestMethod]
    public void Verify_TamperedSignedAssembly_ReturnsInvalid()
    {
        var (tamperedAssembly, _) = CreateSignedAssembly();

        try
        {
            byte[] image = File.ReadAllBytes(tamperedAssembly);
            image[0x40] ^= 0x01;
            File.WriteAllBytes(tamperedAssembly, image);

            var verifier = new StrongNameSignatureVerifier();
            Assert.AreEqual(
                StrongNameSignatureVerificationResult.Invalid,
                verifier.Verify(tamperedAssembly, force: true));
        }
        finally
        {
            File.Delete(tamperedAssembly);
        }
    }

    [TestMethod]
    public void Verify_TamperedSignature_ReturnsInvalid()
    {
        var (signedAssembly, _) = CreateSignedAssembly();

        try
        {
            byte[] image = File.ReadAllBytes(signedAssembly);
            using var peReader = new PEReader(new MemoryStream(image));
            DirectoryEntry signatureDirectory = peReader.PEHeaders.CorHeader!.StrongNameSignatureDirectory;
            Assert.IsTrue(peReader.PEHeaders.TryGetDirectoryOffset(signatureDirectory, out int signatureOffset));
            image[signatureOffset] ^= 0x01;
            File.WriteAllBytes(signedAssembly, image);

            var verifier = new StrongNameSignatureVerifier();
            Assert.AreEqual(
                StrongNameSignatureVerificationResult.Invalid,
                verifier.Verify(signedAssembly, force: true));
        }
        finally
        {
            File.Delete(signedAssembly);
        }
    }

    [TestMethod]
    public void Verify_ChecksumAndSecurityDirectoryChanges_RemainsValid()
    {
        var (signedAssembly, _) = CreateSignedAssembly();

        try
        {
            byte[] image = File.ReadAllBytes(signedAssembly);
            using var peReader = new PEReader(new MemoryStream(image));
            PEHeaders headers = peReader.PEHeaders;
            int optionalHeaderOffset = headers.CoffHeaderStartOffset + 20;
            int checksumOffset = optionalHeaderOffset + 64;
            int directoriesOffset = optionalHeaderOffset
                + (headers.PEHeader!.Magic == PEMagic.PE32 ? 96 : 112);
            int securityEntryOffset = directoriesOffset + 4 * 8;
            image[checksumOffset] ^= 0x01;
            image[securityEntryOffset] ^= 0x01;
            File.WriteAllBytes(signedAssembly, image);

            var verifier = new StrongNameSignatureVerifier();
            Assert.AreEqual(StrongNameSignatureVerificationResult.Valid, verifier.Verify(signedAssembly));
        }
        finally
        {
            File.Delete(signedAssembly);
        }
    }

    [TestMethod]
    public void Verify_RegisteredAssembly_IsSkippedUnlessForceIsSet()
    {
        var (signedAssembly, _) = CreateSignedAssembly();
        var verifier = new StrongNameSignatureVerifier(new AlwaysSkipVerificationList());

        try
        {
            Assert.AreEqual(
                StrongNameSignatureVerificationResult.Skipped,
                verifier.Verify(signedAssembly));
            Assert.AreEqual(
                StrongNameSignatureVerificationResult.Valid,
                verifier.Verify(signedAssembly, force: true));
        }
        finally
        {
            File.Delete(signedAssembly);
        }
    }

    [TestMethod]
    public void ForceOption_IsHiddenOnlyWhenNotRunningOnWindows()
    {
        var nonWindowsParser = NomDePlumeRootCommand.CreateParser(isWindows: false);
        var windowsParser = NomDePlumeRootCommand.CreateParser(isWindows: true);

        Assert.IsTrue(GetForceOption(nonWindowsParser.RootCommand.Subcommands.Single()).Hidden);
        Assert.IsFalse(GetForceOption(windowsParser.RootCommand.Subcommands.Single()).Hidden);
    }

    [TestMethod]
    public void RegistrySkipEntry_MatchesAssemblyAndWildcardForItsToken()
    {
        const string assemblyPath = @"C:\dev\Example.dll";
        const string token = "0123456789abcdef";

        Assert.IsTrue(StrongNameVerificationSkipEntry.Matches(
            $"Example,{token}", assemblyPath, "Example", token));
        Assert.IsTrue(StrongNameVerificationSkipEntry.Matches(
            $"*,{token}", assemblyPath, "Example", token));
        Assert.IsFalse(StrongNameVerificationSkipEntry.Matches(
            $"Example,ffffffffffffffff", assemblyPath, "Example", token));
        Assert.IsFalse(StrongNameVerificationSkipEntry.Matches(
            $"Other,{token}", assemblyPath, "Example", token));
    }

    [TestMethod]
    public void StrongNameHasher_ZeroesHeaderFieldsAndExcludesSignatureBytes()
    {
        byte[] image = File.ReadAllBytes(typeof(StrongNameSignatureVerifierTests).Assembly.Location);
        using var peReader = new PEReader(new MemoryStream(image));
        PEHeaders headers = peReader.PEHeaders;
        int optionalHeaderOffset = headers.CoffHeaderStartOffset + 20;
        int checksumOffset = optionalHeaderOffset + 64;
        int directoriesOffset = optionalHeaderOffset
            + (headers.PEHeader!.Magic == PEMagic.PE32 ? 96 : 112);
        int securityEntryOffset = directoriesOffset + 4 * 8;

        byte[] baselineHash = StrongNameHasher.ComputeHash(
            image,
            headers,
            new DirectoryEntry(0, 0),
            HashAlgorithmName.SHA256);
        byte[] changedHeader = [.. image];
        changedHeader[checksumOffset] ^= 0x01;
        changedHeader[securityEntryOffset] ^= 0x01;
        byte[] headerHash = StrongNameHasher.ComputeHash(
            changedHeader,
            headers,
            new DirectoryEntry(0, 0),
            HashAlgorithmName.SHA256);

        Assert.IsTrue(baselineHash.SequenceEqual(headerHash));

        SectionHeader section = headers.SectionHeaders[0];
        var signatureDirectory = new DirectoryEntry(section.VirtualAddress, 1);
        Assert.IsTrue(headers.TryGetDirectoryOffset(signatureDirectory, out int signatureOffset));
        byte[] changedSignature = [.. image];
        changedSignature[signatureOffset] ^= 0x01;
        byte[] signatureHash = StrongNameHasher.ComputeHash(
            changedSignature,
            headers,
            signatureDirectory,
            HashAlgorithmName.SHA256);

        byte[] unmodifiedSignatureHash = StrongNameHasher.ComputeHash(
            image,
            headers,
            signatureDirectory,
            HashAlgorithmName.SHA256);
        Assert.IsTrue(unmodifiedSignatureHash.SequenceEqual(signatureHash));
    }

    private static System.CommandLine.Option GetForceOption(System.CommandLine.Command command)
        => command.Options.Single(option => option.Name == "--force");

    private static (string Path, byte[] SigningHash) CreateSignedAssembly(HashAlgorithmName? hashAlgorithm = null)
    {
        HashAlgorithmName signatureHashAlgorithm = hashAlgorithm ?? HashAlgorithmName.SHA1;
        using RSA rsa = RSA.Create(1024);
        RSAParameters key = rsa.ExportParameters(includePrivateParameters: true);
        byte[] publicKey = CreateStrongNamePublicKey(key, signatureHashAlgorithm);
        byte[] signingHash = [];

        var metadata = new MetadataBuilder();
        metadata.AddModule(
            0,
            metadata.GetOrAddString("SignedFixture.dll"),
            metadata.GetOrAddGuid(Guid.NewGuid()),
            default,
            default);
        metadata.AddAssembly(
            metadata.GetOrAddString("SignedFixture"),
            new Version(1, 0, 0, 0),
            default,
            metadata.GetOrAddBlob(publicKey),
            AssemblyFlags.PublicKey,
            AssemblyHashAlgorithm.Sha1);
        metadata.AddTypeDefinition(
            default,
            default,
            metadata.GetOrAddString("<Module>"),
            default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        var peBuilder = new ManagedPEBuilder(
            new PEHeaderBuilder(imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll),
            new MetadataRootBuilder(metadata),
            new BlobBuilder(),
            strongNameSignatureSize: rsa.KeySize / 8,
            flags: CorFlags.ILOnly | CorFlags.StrongNameSigned);
        var peImage = new BlobBuilder();
        peBuilder.Serialize(peImage);
        peBuilder.Sign(peImage, content =>
        {
            using IncrementalHash hash = IncrementalHash.CreateHash(signatureHashAlgorithm);
            foreach (Blob blob in content)
            {
                hash.AppendData(blob.GetBytes().AsSpan());
            }

            signingHash = hash.GetHashAndReset();
            byte[] signature = rsa.SignHash(
                signingHash,
                signatureHashAlgorithm,
                RSASignaturePadding.Pkcs1);
            Array.Reverse(signature);
            return signature;
        });

        string path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.dll");
        using var output = File.Create(path);
        peImage.WriteContentTo(output);
        return (path, signingHash);
    }

    private static byte[] CreateStrongNamePublicKey(RSAParameters parameters, HashAlgorithmName hashAlgorithm)
    {
        byte[] modulus = parameters.Modulus!.Reverse().ToArray();
        if (parameters.Exponent!.Length > sizeof(uint))
        {
            throw new FormatException("The generated RSA public exponent is too large for a CAPI key blob.");
        }

        Span<byte> exponentBytes = stackalloc byte[sizeof(uint)];
        parameters.Exponent.CopyTo(exponentBytes[(sizeof(uint) - parameters.Exponent.Length)..]);
        uint exponent = BinaryPrimitives.ReadUInt32BigEndian(exponentBytes);
        byte[] publicKeyBlob = new byte[20 + modulus.Length];
        publicKeyBlob[0] = (byte)BlobType.PUBLICKEYBLOB;
        publicKeyBlob[1] = 2;
        BinaryPrimitives.WriteUInt32LittleEndian(
            publicKeyBlob.AsSpan(4),
            (uint)KeySigningAlgorithm.CALG_RSA_SIGN);
        BinaryPrimitives.WriteUInt32LittleEndian(publicKeyBlob.AsSpan(8), (uint)RsaMagic.RSA1);
        BinaryPrimitives.WriteUInt32LittleEndian(publicKeyBlob.AsSpan(12), (uint)(modulus.Length * 8));
        BinaryPrimitives.WriteUInt32LittleEndian(publicKeyBlob.AsSpan(16), exponent);
        modulus.CopyTo(publicKeyBlob, 20);

        byte[] publicKey = new byte[12 + publicKeyBlob.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(publicKey, (uint)KeySigningAlgorithm.CALG_RSA_SIGN);
        KeyHashAlgorithm keyHashAlgorithm = hashAlgorithm == HashAlgorithmName.SHA1
            ? KeyHashAlgorithm.CALG_SHA1
            : KeyHashAlgorithm.CALG_SHA_256;
        BinaryPrimitives.WriteUInt32LittleEndian(publicKey.AsSpan(4), (uint)keyHashAlgorithm);
        BinaryPrimitives.WriteUInt32LittleEndian(publicKey.AsSpan(8), (uint)publicKeyBlob.Length);
        publicKeyBlob.CopyTo(publicKey, 12);
        return publicKey;
    }

    private sealed class AlwaysSkipVerificationList : IStrongNameVerificationSkipList
    {
        public bool IsVerificationSkipped(string assemblyPath, string assemblyName, string publicKeyToken) => true;
    }
}
