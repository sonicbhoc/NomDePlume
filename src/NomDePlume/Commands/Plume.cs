using DotMake.CommandLine;
using System.CommandLine;

namespace NomDePlume.Commands;

[CliCommand(
    Description = "Nom de Plume is a cross-platform utility for signing and inspecting .NET assemblies with Strong Naming Keys.")]
public class Plume
{
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
