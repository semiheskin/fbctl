using fbctl.Commands;
using Microsoft.Extensions.Configuration;
using Spectre.Console.Cli;

internal class Program
{
    private static async Task Main(string[] args)
    {
        var env = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");
        var builder = new ConfigurationBuilder()
            .AddJsonFile($"appsettings.json", true, true)
            .AddJsonFile($"appsettings.{env}.json", true, true);

        var appsettings = builder.Build();

        var app = new CommandApp();

        app.Configure(config =>
        {
            config.SetApplicationName("fbctl");
            config.AddBranch("bidirrep", bidirrep =>
            {
                bidirrep.AddCommand<BiDirRepValidateCommand>("validate").WithData(appsettings);
                bidirrep.AddCommand<BiDirRepCreateCommand>("create").WithData(appsettings);
            });
        });

        await app.RunAsync(args);
    }
}