using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace NomDePlume.SignatureVerification;

public class StrongNameSignatureVerifier : IStrongNameSignatureVerifier
{
    public async Task<SignatureVerificationResult> VerifyAssemblyStrongNamingAsync(FilePath assemblyPath)
    {
        if (!assemblyPath.Exists)
        {
            return new AssemblyFileNotFound(assemblyPath);
        }

        await using FileStream peFile = new(assemblyPath, FileMode.Open);
        using PEReader peReader = new(peFile);

        if (peReader.PEHeaders.CorHeader is null)
        {
            return new CorHeaderNotFound(assemblyPath);
        }

        if (!peReader.PEHeaders.CorHeader.Flags.HasFlag(CorFlags.StrongNameSigned))
        {
            return new CorStrongNameFlagUnset(assemblyPath);
        }

        if (!peReader.HasMetadata)
        {
            return new PEHeaderEmpty(assemblyPath);
        }
        
        var mdReader = peReader.GetMetadataReader();

        if (!mdReader.IsAssembly)
        {
            return new NotAnAssembly(assemblyPath);
        }

        AssemblyDefinition assemblyDefinition = mdReader.GetAssemblyDefinition();

        string name = mdReader.GetString(assemblyDefinition.Name);
        
        BlobReader publicKey = mdReader.GetBlobReader(assemblyDefinition.PublicKey);
        publicKey
    }
}
