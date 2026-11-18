using System.CommandLine;
using DotMake.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using NomDePlume.StrongNaming;

namespace NomDePlume.Commands;

[CliCommand(Children = new[] { typeof(AssemblyVerificationCommand) })]
public sealed class NomDePlumeRootCommand
{
    public static void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton<IStrongNameVerificationSkipList, WindowsRegistryStrongNameVerificationSkipList>();
        services.AddSingleton<IStrongNameSignatureVerifier, StrongNameSignatureVerifier>();
    }

    public static CliParser CreateParser(bool isWindows)
    {
        CliParser parser = Cli.GetParser<NomDePlumeRootCommand>();
        Command verificationCommand = parser.RootCommand.Subcommands
            .Single(command => command.Name == "verify");
        Option forceOption = verificationCommand.Options
            .Single(option => option.Name == "--force");

        forceOption.Hidden = !isWindows;
        return parser;
    }
}
