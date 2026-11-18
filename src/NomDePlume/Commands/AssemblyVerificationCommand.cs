using DotMake.CommandLine;

using NomDePlume.SignatureVerification;

namespace NomDePlume.Commands;

[CliCommand(
    Parent = typeof(Plume),
    Name = "verify",
    Description = "Verify an assembly's strong-name signature.")]
public sealed class AssemblyVerificationCommand(IStrongNameSignatureVerifier verifier)
{
    [CliArgument(
        Required = true,
        ValidationRules = CliValidationRules.LegalPath,
        Description = "Path to a valid .NET assembly file")]
    public FilePath AssemblyPath { get; set; }

    [CliOption(
        Alias = "-f",
        Description = "Force signature verification even when Windows registry policy skips it.",
        Hidden = true)]
    public bool Force { get; set; }

    public async Task<int> RunAsync()
    {
        SignatureVerificationResult result =
            await verifier.VerifyAssemblyStrongNamingAsync(AssemblyPath, Force).ConfigureAwait(false);
        var failure = (
            ExitCode: 1,
            Message: $"Failed to verify assembly -- Strong name validation failed: {AssemblyPath.Value}");
        (int exitCode, string message) = result switch
        {
            StrongNameSignatureValid => (0, $"{AssemblyPath.Value} is valid."),
            StrongNameVerificationSkipped =>
                (0, $"Strong-name verification skipped by Windows registry policy: {AssemblyPath.Value}"),
            AssemblyFileNotFound notFound => (1, $"Assembly file not found: {notFound.Path.Value}"),
            CorStrongNameFlagUnset => failure,
            StrongNameSignatureInvalid => failure,
            StrongNameHasherError hasherError => (1, FormatError(hasherError))
        };

        if (exitCode == 0)
        {
            await Console.Out.WriteLineAsync(message);
        }
        else
        {
            await Console.Error.WriteLineAsync(message);
        }

        return exitCode;
    }

    private static string FormatError(StrongNameHasherError error) => error switch
    {
        PEHeaderEmpty missingMetadata => $"Assembly has no metadata: {missingMetadata.Path.Value}",
        NotAnAssembly notAssembly => $"File is not a .NET assembly: {notAssembly.Path.Value}",
        CorHeaderNotFound missingHeader => $"Assembly has no COR header: {missingHeader.Path.Value}",
        StrongNamePublicKeyMissing missingKey => $"Assembly has no strong-name public key: {missingKey.Path.Value}",
        UnsupportedStrongNameHashAlgorithm unsupported =>
            $"Unsupported strong-name hash algorithm '{unsupported.Algorithm}': {unsupported.Path.Value}",
        InvalidStrongNameSignatureDirectory invalidDirectory =>
            $"Invalid strong-name signature directory for {invalidDirectory.Path.Value}: {invalidDirectory.Reason}",
        InvalidStrongNamePublicKey invalidKey =>
            $"Invalid strong-name public key for {invalidKey.Path.Value}: {invalidKey.Reason}",
        InvalidStrongNameImage invalidImage =>
            $"Invalid strong-name image {invalidImage.Path.Value}: {invalidImage.Reason}"
    };
}
