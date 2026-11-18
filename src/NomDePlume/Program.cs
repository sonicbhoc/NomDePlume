using DotMake.CommandLine;
using NomDePlume.Commands;

CliParser parser = NomDePlumeRootCommand.CreateParser(OperatingSystem.IsWindows());
return parser.Run(args);