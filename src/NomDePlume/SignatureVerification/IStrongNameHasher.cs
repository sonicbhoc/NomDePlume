using System.Reflection.PortableExecutable;

namespace NomDePlume.SignatureVerification;

public interface IStrongNameHasher
{
    StrongNameHashComputationResult ComputePeStrongNameHash(PEReader peReader, FilePath assemblyPath);
}
