using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;

using Microsoft.Extensions.DependencyInjection;

using NomDePlume.Capi;
using NomDePlume.Commands;
using NomDePlume.StrongNaming;
using NomDePlume.StrongNamingKey;

namespace NomDePlume.Tests;

[TestClass]
[DoNotParallelize]
public sealed class StrongNameSignatureVerifierTests
{
    [TestMethod]
    public async Task VerifyAssemblyStrongNamingAsync_SignedAssembly_ReturnsValid()
    {
        (FilePath signedAssembly, byte[] signingHash) = CreateSignedAssembly();

        try
        {
            byte[] image = await File.ReadAllBytesAsync(signedAssembly.Value, TestContext.CancellationToken);
            using var peReader = new PEReader(new MemoryStream(image));
            byte[] computedHash = ComputeHash(
                image,
                peReader.PEHeaders,
                peReader.PEHeaders.CorHeader!.StrongNameSignatureDirectory,
                HashAlgorithmName.SHA1);
            Assert.AreSequenceEqual(signingHash, computedHash);
            StrongNameHashComputationResult hashResult =
                StrongNameHasher.ComputePeStrongNameHash(peReader, signedAssembly);
            Assert.IsTrue(hashResult.TryGetValue(out StrongNameHashData reusableHash));
            Assert.IsFalse(hashResult.TryGetValue(out StrongNameHasherError _));
            Assert.AreSequenceEqual(signingHash, reusableHash.Hash);
            Assert.AreEqual(HashAlgorithmName.SHA1, reusableHash.AlgorithmName);
            Assert.IsGreaterThanOrEqualTo(0, reusableHash.SignatureOffset);
            Assert.IsGreaterThan(0, reusableHash.SignatureLength);

            var verifier = new StrongNameSignatureVerifier(
                new WindowsRegistryStrongNameVerificationSkipList());

            StrongNameSignatureVerificationResult result =
                await verifier.VerifyAssemblyStrongNamingAsync(signedAssembly);
            Assert.IsTrue(result is StrongNameSignatureValid);
        }
        finally
        {
            File.Delete(signedAssembly.Value);
        }
    }

    [TestMethod]
    public async Task VerifyAssemblyStrongNamingAsync_Sha256SignedAssembly_ReturnsValid()
    {
        (FilePath signedAssembly, _) = CreateSignedAssembly(HashAlgorithmName.SHA256);

        try
        {
            var verifier = new StrongNameSignatureVerifier(
                new WindowsRegistryStrongNameVerificationSkipList());

            StrongNameSignatureVerificationResult result =
                await verifier.VerifyAssemblyStrongNamingAsync(signedAssembly);
            Assert.IsTrue(result is StrongNameSignatureValid);
        }
        finally
        {
            File.Delete(signedAssembly.Value);
        }
    }

    [TestMethod]
    public async Task VerifyAssemblyStrongNamingAsync_TamperedAssembly_ReturnsInvalid()
    {
        (FilePath tamperedAssembly, _) = CreateSignedAssembly();

        try
        {
            byte[] image = await File.ReadAllBytesAsync(tamperedAssembly.Value, TestContext.CancellationToken);
            image[0x40] ^= 0x01;
            await File.WriteAllBytesAsync(tamperedAssembly.Value, image, TestContext.CancellationToken);

            var verifier = new StrongNameSignatureVerifier(
                new WindowsRegistryStrongNameVerificationSkipList());
            StrongNameSignatureVerificationResult result =
                await verifier.VerifyAssemblyStrongNamingAsync(tamperedAssembly, force: true);
            Assert.IsTrue(result is StrongNameSignatureInvalid);
        }
        finally
        {
            File.Delete(tamperedAssembly.Value);
        }
    }

    [TestMethod]
    public async Task VerifyAssemblyStrongNamingAsync_TamperedSignature_ReturnsInvalid()
    {
        (FilePath signedAssembly, _) = CreateSignedAssembly();

        try
        {
            byte[] image = await File.ReadAllBytesAsync(signedAssembly.Value, TestContext.CancellationToken);
            using var peReader = new PEReader(new MemoryStream(image));
            DirectoryEntry signatureDirectory = peReader.PEHeaders.CorHeader!.StrongNameSignatureDirectory;
            Assert.IsTrue(peReader.PEHeaders.TryGetDirectoryOffset(signatureDirectory, out int signatureOffset));
            image[signatureOffset] ^= 0x01;
            await File.WriteAllBytesAsync(signedAssembly.Value, image, TestContext.CancellationToken);

            var verifier = new StrongNameSignatureVerifier(
                new WindowsRegistryStrongNameVerificationSkipList());
            StrongNameSignatureVerificationResult result =
                await verifier.VerifyAssemblyStrongNamingAsync(signedAssembly, force: true);
            Assert.IsTrue(result is StrongNameSignatureInvalid);
        }
        finally
        {
            File.Delete(signedAssembly.Value);
        }
    }

    [TestMethod]
    public async Task VerifyAssemblyStrongNamingAsync_ChecksumAndSecurityDirectoryChanges_RemainsValid()
    {
        (FilePath signedAssembly, _) = CreateSignedAssembly();

        try
        {
            byte[] image = await File.ReadAllBytesAsync(signedAssembly.Value, TestContext.CancellationToken);
            using var peReader = new PEReader(new MemoryStream(image));
            PEHeaders headers = peReader.PEHeaders;
            int optionalHeaderOffset = headers.CoffHeaderStartOffset + 20;
            int checksumOffset = optionalHeaderOffset + 64;
            int directoriesOffset = optionalHeaderOffset
                + (headers.PEHeader!.Magic == PEMagic.PE32 ? 96 : 112);
            int securityEntryOffset = directoriesOffset + 4 * 8;
            image[checksumOffset] ^= 0x01;
            image[securityEntryOffset] ^= 0x01;
            await File.WriteAllBytesAsync(signedAssembly.Value, image, TestContext.CancellationToken);

            var verifier = new StrongNameSignatureVerifier(
                new WindowsRegistryStrongNameVerificationSkipList());
            StrongNameSignatureVerificationResult result =
                await verifier.VerifyAssemblyStrongNamingAsync(signedAssembly);
            Assert.IsTrue(result is StrongNameSignatureValid);
        }
        finally
        {
            File.Delete(signedAssembly.Value);
        }
    }

    [TestMethod]
    public async Task VerifyAssemblyStrongNamingAsync_RegisteredAssembly_IsSkippedUnlessForceIsSet()
    {
        (FilePath signedAssembly, _) = CreateSignedAssembly();
        var verifier = new StrongNameSignatureVerifier(
            new AlwaysSkipVerificationList());

        try
        {
            StrongNameSignatureVerificationResult skipped =
                await verifier.VerifyAssemblyStrongNamingAsync(signedAssembly);
            StrongNameSignatureVerificationResult forced =
                await verifier.VerifyAssemblyStrongNamingAsync(signedAssembly, force: true);

            Assert.IsTrue(skipped is StrongNameVerificationSkipped);
            Assert.IsTrue(forced is StrongNameSignatureValid);
        }
        finally
        {
            File.Delete(signedAssembly.Value);
        }
    }

    [TestMethod]
    public async Task VerifyAssemblyStrongNamingAsync_MissingPath_ReturnsFileNotFoundWithTypedPath()
    {
        var assemblyPath = new FilePath(Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.dll"));
        var verifier = new StrongNameSignatureVerifier(new WindowsRegistryStrongNameVerificationSkipList());

        StrongNameSignatureVerificationResult result =
            await verifier.VerifyAssemblyStrongNamingAsync(assemblyPath);

        Assert.IsTrue(result is AssemblyFileNotFound);
        Assert.AreEqual(assemblyPath, ((AssemblyFileNotFound)result.Value!).Path);
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
    public void ConfigureServices_ResolvesVerifierAndItsDependencies()
    {
        var services = new ServiceCollection();
        NomDePlumeRootCommand.ConfigureServices(services);

        using ServiceProvider provider = services.BuildServiceProvider();

        IStrongNameSignatureVerifier verifier = provider.GetRequiredService<IStrongNameSignatureVerifier>();
        IStrongNameVerificationSkipList skipList =
            provider.GetRequiredService<IStrongNameVerificationSkipList>();

        Assert.IsInstanceOfType<StrongNameSignatureVerifier>(verifier);
        Assert.IsInstanceOfType<WindowsRegistryStrongNameVerificationSkipList>(skipList);
    }

    [TestMethod]
    public void SignatureVerificationResult_UsesTypedPatternMatchingAndHandlesDefault()
    {
        var assemblyPath = new FilePath("signed.dll");
        StrongNameSignatureVerificationResult result = new StrongNameSignatureValid(assemblyPath);

        Assert.IsTrue(result.HasValue);
        Assert.IsTrue(result.TryGetValue(out StrongNameSignatureValid valid));
        Assert.AreEqual(assemblyPath, valid.Path);
        Assert.IsFalse(result.TryGetValue(out StrongNameHasherError _));

        StrongNameSignatureVerificationResult empty = default;
        Assert.IsFalse(empty.HasValue);
        Assert.IsNull(empty.Value);
        Assert.IsFalse(empty.TryGetValue(out StrongNameHasherError _));
    }

    [TestMethod]
    public void StrongNameSignatureVerificationResult_ValueReturnsEachDeclaredCase()
    {
        var assemblyPath = new FilePath("signed.dll");
        (StrongNameSignatureVerificationResult Result, Type CaseType)[] cases =
        [
            (new AssemblyFileNotFound(assemblyPath), typeof(AssemblyFileNotFound)),
            (new StrongNameHasherError(new CorHeaderNotFound(assemblyPath)), typeof(StrongNameHasherError)),
            (new CorStrongNameFlagUnset(assemblyPath), typeof(CorStrongNameFlagUnset)),
            (new StrongNameHasherError(new PEHeaderEmpty(assemblyPath)), typeof(StrongNameHasherError)),
            (new StrongNameHasherError(new NotAnAssembly(assemblyPath)), typeof(StrongNameHasherError)),
            (new StrongNameSignatureInvalid(assemblyPath), typeof(StrongNameSignatureInvalid)),
            (new StrongNameSignatureValid(assemblyPath), typeof(StrongNameSignatureValid)),
            (new StrongNameVerificationSkipped(assemblyPath), typeof(StrongNameVerificationSkipped))
        ];

        foreach ((StrongNameSignatureVerificationResult result, Type caseType) in cases)
        {
            object? value = result.Value;
            Assert.AreEqual(caseType, value?.GetType());
            FilePath resultPath = value switch
            {
                AssemblyFileNotFound item => item.Path,
                StrongNameHasherError item => GetPath(item),
                CorStrongNameFlagUnset item => item.Path,
                StrongNameSignatureInvalid item => item.Path,
                StrongNameSignatureValid item => item.Path,
                StrongNameVerificationSkipped item => item.Path,
                _ => default
            };
            Assert.AreEqual(assemblyPath, resultPath);
        }
    }

    private static FilePath GetPath(StrongNameHasherError error)
    {
        if (error.TryGetValue(out PEHeaderEmpty peHeaderEmpty))
        {
            return peHeaderEmpty.Path;
        }

        if (error.TryGetValue(out NotAnAssembly notAnAssembly))
        {
            return notAnAssembly.Path;
        }

        if (error.TryGetValue(out CorHeaderNotFound corHeaderNotFound))
        {
            return corHeaderNotFound.Path;
        }

        Assert.Fail("The expected shared hasher error case was not present.");
        return default;
    }

    [TestMethod]
    public void RegistrySkipEntry_MatchesAssemblyAndWildcardForItsToken()
    {
        var assemblyPath = new FilePath(@"C:\dev\Example.dll");
        const string token = "0123456789abcdef";

        Assert.IsTrue(StrongNameVerificationSkipEntry.Matches(
            $"Example,{token}", assemblyPath, "Example", token));
        Assert.IsTrue(StrongNameVerificationSkipEntry.Matches(
            $"*,{token}", assemblyPath, "Example", token));
        Assert.IsFalse(StrongNameVerificationSkipEntry.Matches(
            $"Example,FFFFFFFFFFFFFFFF", assemblyPath, "Example", token));
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

        byte[] baselineHash = ComputeHash(
            image,
            headers,
            new DirectoryEntry(0, 0),
            HashAlgorithmName.SHA256);
        byte[] changedHeader = [.. image];
        changedHeader[checksumOffset] ^= 0x01;
        changedHeader[securityEntryOffset] ^= 0x01;
        byte[] headerHash = ComputeHash(
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
        byte[] signatureHash = ComputeHash(
            changedSignature,
            headers,
            signatureDirectory,
            HashAlgorithmName.SHA256);

        byte[] unmodifiedSignatureHash = ComputeHash(
            image,
            headers,
            signatureDirectory,
            HashAlgorithmName.SHA256);
        Assert.IsTrue(unmodifiedSignatureHash.SequenceEqual(signatureHash));
    }

    [TestMethod]
    public void StrongNameHasher_ModuleWithoutAssemblyDefinition_ReturnsTypedNotAnAssemblyError()
    {
        using var peReader = new PEReader(new MemoryStream(CreateModuleWithoutAssemblyDefinition()));
        var assemblyPath = new FilePath("ModuleFixture.netmodule");

        StrongNameHashComputationResult result =
            StrongNameHasher.ComputePeStrongNameHash(peReader, assemblyPath);

        Assert.IsFalse(result.TryGetValue(out StrongNameHashData _));
        Assert.IsTrue(result.TryGetValue(out StrongNameHasherError error));
        Assert.IsTrue(error.TryGetValue(out NotAnAssembly notAnAssembly));
        Assert.AreEqual(assemblyPath, notAnAssembly.Path);
    }

    [TestMethod]
    public void StrongNameHasher_ImageWithoutMetadata_ReturnsTypedMetadataError()
    {
        (FilePath assemblyPath, _) = CreateSignedAssembly();
        try
        {
            byte[] image = File.ReadAllBytes(assemblyPath.Value);
            using (var originalReader = new PEReader(new MemoryStream(image)))
            {
                PEHeaders headers = originalReader.PEHeaders;
                int optionalHeaderOffset = headers.CoffHeaderStartOffset + 20;
                int dataDirectoriesOffset = optionalHeaderOffset
                    + (headers.PEHeader!.Magic == PEMagic.PE32 ? 96 : 112);
                int corHeaderDirectoryOffset = dataDirectoriesOffset + 14 * 8;
                image.AsSpan(corHeaderDirectoryOffset, 8).Clear();
            }

            using var peReader = new PEReader(new MemoryStream(image));
            Assert.IsFalse(peReader.HasMetadata);

            StrongNameHashComputationResult result =
                StrongNameHasher.ComputePeStrongNameHash(peReader, assemblyPath);

            Assert.IsTrue(result.TryGetValue(out StrongNameHasherError error));
            Assert.IsTrue(error.TryGetValue(out PEHeaderEmpty noMetadata));
            Assert.AreEqual(assemblyPath, noMetadata.Path);
        }
        finally
        {
            File.Delete(assemblyPath.Value);
        }
    }

    [TestMethod]
    public void StrongNameHasher_UnsupportedPublicKeyAlgorithm_ReturnsTypedErrorWithAlgorithm()
    {
        const KeyHashAlgorithm unsupportedAlgorithm = (KeyHashAlgorithm)0xDEADBEEF;
        (FilePath assemblyPath, _) = CreateSignedAssembly(keyHashAlgorithmOverride: unsupportedAlgorithm);

        try
        {
            byte[] image = File.ReadAllBytes(assemblyPath.Value);
            using var peReader = new PEReader(new MemoryStream(image));

            StrongNameHashComputationResult result =
                StrongNameHasher.ComputePeStrongNameHash(peReader, assemblyPath);

            Assert.IsFalse(result.TryGetValue(out StrongNameHashData _));
            Assert.IsTrue(result.TryGetValue(out StrongNameHasherError error));
            Assert.IsTrue(
                error.TryGetValue(out UnsupportedStrongNameHashAlgorithm unsupported),
                "The unsupported algorithm must be returned as a typed domain error.");
            Assert.AreEqual(assemblyPath, unsupported.Path);
            Assert.AreEqual(unsupportedAlgorithm.ToString(), unsupported.Algorithm);
        }
        finally
        {
            File.Delete(assemblyPath.Value);
        }
    }

    [TestMethod]
    public void StrongNameHasher_MissingStrongNameSignatureDirectory_ReturnsTypedDirectoryError()
    {
        (FilePath assemblyPath, _) = CreateSignedAssembly(includeStrongNameSignature: false);

        try
        {
            byte[] image = File.ReadAllBytes(assemblyPath.Value);
            using var peReader = new PEReader(new MemoryStream(image));

            StrongNameHashComputationResult result =
                StrongNameHasher.ComputePeStrongNameHash(peReader, assemblyPath);

            Assert.IsFalse(result.TryGetValue(out StrongNameHashData _));
            Assert.IsTrue(result.TryGetValue(out StrongNameHasherError error));
            Assert.IsTrue(error.TryGetValue(out InvalidStrongNameSignatureDirectory invalidDirectory));
            Assert.AreEqual(assemblyPath, invalidDirectory.Path);
            Assert.Contains("signature directory", invalidDirectory.Reason);
        }
        finally
        {
            File.Delete(assemblyPath.Value);
        }
    }

    [TestMethod]
    public void StrongNameHasher_MissingPublicKey_ReturnsTypedPublicKeyError()
    {
        (FilePath assemblyPath, _) = CreateSignedAssembly(includePublicKey: false, includeStrongNameSignature: false);

        try
        {
            byte[] image = File.ReadAllBytes(assemblyPath.Value);
            using var peReader = new PEReader(new MemoryStream(image));

            StrongNameHashComputationResult result =
                StrongNameHasher.ComputePeStrongNameHash(peReader, assemblyPath);

            Assert.IsFalse(result.TryGetValue(out StrongNameHashData _));
            Assert.IsTrue(result.TryGetValue(out StrongNameHasherError error));
            Assert.IsTrue(error.TryGetValue(out StrongNamePublicKeyMissing missingPublicKey));
            Assert.AreEqual(assemblyPath, missingPublicKey.Path);
        }
        finally
        {
            File.Delete(assemblyPath.Value);
        }
    }

    [TestMethod]
    public void StrongNameHasher_MalformedPublicKey_ReturnsTypedErrorWithReason()
    {
        (FilePath assemblyPath, _) = CreateSignedAssembly(
            includeStrongNameSignature: false,
            publicKeyOverride: [0x01]);

        try
        {
            byte[] image = File.ReadAllBytes(assemblyPath.Value);
            using var peReader = new PEReader(new MemoryStream(image));

            StrongNameHashComputationResult result =
                StrongNameHasher.ComputePeStrongNameHash(peReader, assemblyPath);

            Assert.IsTrue(result.TryGetValue(out StrongNameHasherError error));
            Assert.IsTrue(error.TryGetValue(out InvalidStrongNamePublicKey invalidPublicKey));
            Assert.AreEqual(assemblyPath, invalidPublicKey.Path);
            Assert.Contains("at least", invalidPublicKey.Reason);
        }
        finally
        {
            File.Delete(assemblyPath.Value);
        }
    }

    [TestMethod]
    public void StrongNameHasher_HashRangeOutsideImage_ReturnsTypedImageError()
    {
        (FilePath assemblyPath, _) = CreateSignedAssembly();

        try
        {
            byte[] image = File.ReadAllBytes(assemblyPath.Value);
            using var peReader = new PEReader(new MemoryStream(image));

            StrongNameHashComputationResult result = StrongNameHasher.ComputeHash(
                ReadOnlySpan<byte>.Empty,
                peReader.PEHeaders,
                new DirectoryEntry(0, 0),
                HashAlgorithmName.SHA256,
                assemblyPath);

            Assert.IsTrue(result.TryGetValue(out StrongNameHasherError error));
            Assert.IsTrue(error.TryGetValue(out InvalidStrongNameImage invalidImage));
            Assert.AreEqual(assemblyPath, invalidImage.Path);
            StringAssert.Contains(invalidImage.Reason, "outside the image");
        }
        finally
        {
            File.Delete(assemblyPath.Value);
        }
    }

    [TestMethod]
    public async Task VerifyAssemblyStrongNamingAsync_HasherReturnsTypedError_ComposesErrorWithPathAndContext()
    {
        const KeyHashAlgorithm unsupportedAlgorithm = (KeyHashAlgorithm)0xDEADBEEF;
        (FilePath signedAssembly, _) = CreateSignedAssembly(keyHashAlgorithmOverride: unsupportedAlgorithm);
        var verifier = new StrongNameSignatureVerifier(new WindowsRegistryStrongNameVerificationSkipList());

        try
        {
            StrongNameSignatureVerificationResult result =
                await verifier.VerifyAssemblyStrongNamingAsync(signedAssembly, force: true);

            Assert.IsTrue(result.TryGetValue(out StrongNameHasherError failure),
                "Hasher failures must remain a typed verifier outcome.");
            Assert.IsFalse(result.TryGetValue(out StrongNameSignatureValid _));
            Assert.IsTrue(failure.TryGetValue(out UnsupportedStrongNameHashAlgorithm nestedError));
            Assert.AreEqual(signedAssembly, nestedError.Path);
            Assert.AreEqual(unsupportedAlgorithm.ToString(), nestedError.Algorithm);
        }
        finally
        {
            File.Delete(signedAssembly.Value);
        }
    }

    [TestMethod]
    public async Task AssemblyVerificationCommand_HasherFailure_ReturnsFailureAndWritesPathAndContext()
    {
        var assemblyPath = new FilePath(Path.Combine(Path.GetTempPath(), "unsupported-hash.dll"));
        const KeyHashAlgorithm unsupportedAlgorithm = (KeyHashAlgorithm)0xDEADBEEF;
        var hasherError = new StrongNameHasherError(
            new UnsupportedStrongNameHashAlgorithm(assemblyPath, unsupportedAlgorithm.ToString()));
        var verifierResult = new StrongNameSignatureVerificationResult(hasherError);
        var command = new AssemblyVerificationCommand(new ReturningResultVerifier(verifierResult))
        {
            Assembly = assemblyPath
        };
        TextWriter originalError = Console.Error;
        await using var capturedError = new StringWriter();

        int exitCode;
        try
        {
            Console.SetError(capturedError);
            exitCode = await command.RunAsync();
        }
        finally
        {
            Console.SetError(originalError);
        }

        Assert.AreEqual(1, exitCode);
        Assert.Contains(
            $"Unsupported strong-name hash algorithm '{unsupportedAlgorithm}': {assemblyPath.Value}",
            capturedError.ToString());
    }

    private static System.CommandLine.Option GetForceOption(System.CommandLine.Command command)
        => command.Options.Single(option => option.Name == "--force");

    private static byte[] ComputeHash(
        ReadOnlySpan<byte> image,
        PEHeaders headers,
        DirectoryEntry signatureDirectory,
        HashAlgorithmName algorithm)
    {
        StrongNameHashComputationResult result = StrongNameHasher.ComputeHash(
            image,
            headers,
            signatureDirectory,
            algorithm,
            new FilePath("StrongNameHasherFixture.dll"));
        Assert.IsTrue(result.TryGetValue(out StrongNameHashData data));
        return data.Hash;
    }

    private static (FilePath Path, byte[] SigningHash) CreateSignedAssembly(
        HashAlgorithmName? hashAlgorithm = null,
        KeyHashAlgorithm? keyHashAlgorithmOverride = null,
        bool includeStrongNameSignature = true,
        bool includePublicKey = true,
        byte[]? publicKeyOverride = null)
    {
        HashAlgorithmName signatureHashAlgorithm = hashAlgorithm ?? HashAlgorithmName.SHA1;
        using RSA rsa = RSA.Create(1024);
        RSAParameters key = rsa.ExportParameters(includePrivateParameters: true);
        byte[] publicKey = publicKeyOverride
            ?? (includePublicKey
                ? CreateStrongNamePublicKey(key, signatureHashAlgorithm, keyHashAlgorithmOverride)
                : []);
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
            includePublicKey ? AssemblyFlags.PublicKey : default,
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
            strongNameSignatureSize: includeStrongNameSignature ? rsa.KeySize / 8 : 0,
            flags: includeStrongNameSignature
                ? CorFlags.ILOnly | CorFlags.StrongNameSigned
                : CorFlags.ILOnly);
        var peImage = new BlobBuilder();
        peBuilder.Serialize(peImage);
        if (includeStrongNameSignature)
        {
            peBuilder.Sign(peImage, content =>
            {
                using IncrementalHash hash = IncrementalHash.CreateHash(signatureHashAlgorithm);
                foreach (Blob blob in content)
                {
                    hash.AppendData(blob.GetBytes().AsSpan());
                }

                signingHash = hash.GetHashAndReset();
                using RSA signingRsa = RSA.Create();
                signingRsa.ImportParameters(key);
                byte[] signature = signingRsa.SignHash(
                    signingHash,
                    signatureHashAlgorithm,
                    RSASignaturePadding.Pkcs1);
                Array.Reverse(signature);
                return signature;
            });
        }

        var path = new FilePath(Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.dll"));
        using var output = File.Create(path.Value);
        peImage.WriteContentTo(output);
        return (path, signingHash);
    }

    private static byte[] CreateModuleWithoutAssemblyDefinition()
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            0,
            metadata.GetOrAddString("ModuleFixture.netmodule"),
            metadata.GetOrAddGuid(Guid.NewGuid()),
            default,
            default);
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
            new BlobBuilder());
        var peImage = new BlobBuilder();
        peBuilder.Serialize(peImage);
        return peImage.ToArray();
    }

    private static byte[] CreateStrongNamePublicKey(
        RSAParameters parameters,
        HashAlgorithmName hashAlgorithm,
        KeyHashAlgorithm? keyHashAlgorithmOverride = null)
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
        KeyHashAlgorithm keyHashAlgorithm = keyHashAlgorithmOverride
            ?? (hashAlgorithm == HashAlgorithmName.SHA1
                ? KeyHashAlgorithm.CALG_SHA1
                : KeyHashAlgorithm.CALG_SHA_256);
        BinaryPrimitives.WriteUInt32LittleEndian(publicKey.AsSpan(4), (uint)keyHashAlgorithm);
        BinaryPrimitives.WriteUInt32LittleEndian(publicKey.AsSpan(8), (uint)publicKeyBlob.Length);
        publicKeyBlob.CopyTo(publicKey, 12);
        return publicKey;
    }

    private sealed class AlwaysSkipVerificationList : IStrongNameVerificationSkipList
    {
        public bool IsVerificationSkipped(FilePath assemblyPath, string assemblyName, string publicKeyToken) => true;
    }

    private sealed class ReturningResultVerifier(StrongNameSignatureVerificationResult result)
        : IStrongNameSignatureVerifier
    {
        public Task<StrongNameSignatureVerificationResult> VerifyAssemblyStrongNamingAsync(
            FilePath assemblyPath,
            bool force = false)
            => Task.FromResult(result);
    }

    public TestContext TestContext { get; set; }
}
