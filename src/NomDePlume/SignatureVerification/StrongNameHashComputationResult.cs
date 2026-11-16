using System.Security.Cryptography;

namespace NomDePlume.SignatureVerification;

public readonly record struct StrongNameHashData(
    byte[] Hash,
    HashAlgorithmName AlgorithmName,
    int SignatureOffset,
    int SignatureLength);


public union StrongNameHashComputationResult(StrongNameHashData);
