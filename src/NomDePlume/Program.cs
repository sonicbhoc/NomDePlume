using DotMake.CommandLine;
using NomDePlume.Commands;

Cli.Ext.ConfigureServices(NomDePlumeRootCommand.ConfigureServices);
CliParser parser = NomDePlumeRootCommand.CreateParser(OperatingSystem.IsWindows());
return await parser.RunAsync(args);
