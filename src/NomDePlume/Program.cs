using DotMake.CommandLine;
using NomDePlume.Commands;

CliParser parser = Plume.CreateParser(OperatingSystem.IsWindows());
return parser.Run(args);