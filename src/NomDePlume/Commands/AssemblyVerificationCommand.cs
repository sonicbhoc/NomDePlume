using DotMake.CommandLine;
using NomDePlume;
using NomDePlume.StrongNaming;

namespace NomDePlume.Commands;

[CliCommand(Name = "verify", Description = "Verifies an assembly's strong-name signature.")]
public class AssemblyVerificationCommand
{
    [CliArgument(Description = "The assembly to verify.", Required = true)]
    public FilePath Assembly { get; set; }

    [CliOption(Alias = "-f", Description = "Force signature verification even when Windows registry policy skips it.", Hidden = true)]
    public bool Force { get; set; }

    public int Run()
    {
        if (!File.Exists(Assembly.Value))
        {
            Console.Error.WriteLine($"Assembly file not found: {Assembly.Value}");
            return 1;
        }

        StrongNameSignatureVerificationResult result =
            new StrongNameSignatureVerifier().Verify(Assembly.Value, Force);

        if (result == StrongNameSignatureVerificationResult.Invalid)
        {
            Console.Error.WriteLine($"Failed to verify assembly -- Strong name validation failed: {Assembly.Value}");
            return 1;
        }

        if (result == StrongNameSignatureVerificationResult.Skipped)
        {
            Console.WriteLine($"Strong-name verification skipped by Windows registry policy: {Assembly.Value}");
            return 0;
        }

        Console.WriteLine($"{Assembly.Value} is valid.");
        return 0;
    }
}
