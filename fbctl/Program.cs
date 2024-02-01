using fbctl;
using fbctl.Commands;
using fbctl.Helpers;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Spectre.Console;
using Spectre.Console.Cli;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IdentityModel.Tokens.Jwt;
using System.Linq.Expressions;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Xml.XPath;

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