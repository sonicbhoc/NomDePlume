using DotMake.CommandLine;
using NomDePlume;
using NomDePlume.SignatureVerification;

namespace NomDePlume.Commands;

[CliCommand(
    Parent = typeof(Plume),
    Name = "verify",
    Description = "Verify an assembly's strong-name signature.")]
public class AssemblyVerificationCommand
{
    [CliArgument(
        Required = true,
        ValidationRules = CliValidationRules.LegalPath | CliValidationRules.ExistingFile,
        Description = "Path to a valid .NET assembly file")]
    public FilePath AssemblyPath { get; set; }

    [CliOption(
        Alias = "-f",
        Description = "Force signature verification even when Windows registry policy skips it.",
        Hidden = true)]
    public bool Force { get; set; }

    public int Run()
    {
        if (!File.Exists(AssemblyPath.Value))
        {
            Console.Error.WriteLine($"Assembly file not found: {AssemblyPath.Value}");
            return 1;
        }

        IStrongNameSignatureVerifier verifier = new StrongNameSignatureVerifier();
        SignatureVerificationResult result = verifier.VerifyAssemblyStrongNaming(AssemblyPath, Force);
        switch (result)
        {
            case StrongNameSignatureValid:
                Console.WriteLine($"{AssemblyPath.Value} is valid.");
                return 0;
            case StrongNameVerificationSkipped:
                Console.WriteLine(
                    $"Strong-name verification skipped by Windows registry policy: {AssemblyPath.Value}");
                return 0;
            default:
                Console.Error.WriteLine(
                    $"Failed to verify assembly -- Strong name validation failed: {AssemblyPath.Value}");
                return 1;
        }

    }
}
