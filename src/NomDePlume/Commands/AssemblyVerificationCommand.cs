using DotMake.CommandLine;

namespace NomDePlume.Commands;

[CliCommand(
    Parent = typeof(Plume),
    Name = "verify",
    Description = "Verify an assembly's strong-name signature.")]
public class AssemblyVerificationCommand
{
    [CliArgument(Required = true, ValidationRules = CliValidationRules.LegalPath | CliValidationRules.ExistingFile,
        Description = "Path to a valid .NET assembly file")]
    public FilePath AssemblyPath { get; set; }
    
    [CliOption(Description = "Windows Only. Force verification regardless of verification-skipping entries in the System registry.")]
    public bool Force { get; set; }
    
    
}
