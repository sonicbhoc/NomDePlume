using System.CommandLine;

using DotMake.CommandLine;

using Microsoft.Extensions.DependencyInjection;

using NomDePlume.SignatureVerification;

namespace NomDePlume.Commands;

[CliCommand(
    Description = "Nom de Plume is a cross-platform utility for signing and inspecting .NET assemblies with Strong Naming Keys.")]
public sealed class Plume
{
    public static void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton<IStrongNameHasher, StrongNameHasher>();
        services.AddSingleton<IStrongNameVerificationSkipList, WindowsRegistryStrongNameVerificationSkipList>();
        services.AddSingleton<IStrongNameSignatureVerifier, StrongNameSignatureVerifier>();
    }

    public static CliParser CreateParser(bool isWindows)
    {
        CliParser parser = Cli.GetParser<Plume>();
        Command verificationCommand = parser.RootCommand.Subcommands
            .Single(command => command.Name == "verify");
        Option forceOption = verificationCommand.Options
            .Single(option => option.Name == "--force");

        forceOption.Hidden = !isWindows;
        return parser;
    }
}
