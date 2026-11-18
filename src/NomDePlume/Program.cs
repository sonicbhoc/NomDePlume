using DotMake.CommandLine;

using NomDePlume.Commands;

Cli.Ext.ConfigureServices(Plume.ConfigureServices);
CliParser parser = Plume.CreateParser(OperatingSystem.IsWindows());
return await parser.RunAsync(args);
