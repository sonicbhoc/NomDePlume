using System.CommandLine;
using DotMake.CommandLine;

namespace NomDePlume.Commands;

[CliCommand(Children = new[] { typeof(AssemblyVerificationCommand) })]
public class NomDePlumeRootCommand
{
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
