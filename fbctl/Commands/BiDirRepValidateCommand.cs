using fbctl.Helpers;
using Microsoft.Extensions.Configuration;
using Spectre.Console;
using Spectre.Console.Cli;

namespace fbctl.Commands
{
    public class BiDirRepValidateCommand : Command<BiDirRepValidateCommand.Settings>
    {
        public class Settings : CommandSettings
        {
            [CommandArgument(0, "<array1>")]
            public string? Array1 { get; init; }

            [CommandArgument(1, "<array2>")]
            public string? Array2 { get; init; }
        }
        
        public override int Execute(CommandContext context, Settings settings)
        {
            if (context.Data is not IConfigurationRoot appsettings)
                return 1;

            var fb1 = FlashBladeSettingsHelper.ConvertToSettings(appsettings.GetSection(Constants.AppSettingsFlashBladesSectionName), settings.Array1!);
            var fb2 = FlashBladeSettingsHelper.ConvertToSettings(appsettings.GetSection(Constants.AppSettingsFlashBladesSectionName), settings.Array2!);

            if (!FlashBladeSettingsHelper.CheckMagementApiNetworkAccess(fb1, fb2)) return 1;
            if (!FlashBladeSettingsHelper.CheckManagementApiVersion(fb1, fb2)) return 1;
            if (!FlashBladeSettingsHelper.CheckLogin(fb1, fb2)) return 1;

            AnsiConsole.WriteLine();

            return 0;
        }

        public override ValidationResult Validate(CommandContext context, Settings settings)
        {
            if (context.Data is not IConfigurationRoot appsettings)
                return ValidationResult.Error("AppSettings file could not be found");

            FlashBladeSettingsHelper.ValidateSettings(appsettings, out ValidationResult result, settings.Array1!, settings.Array2!);
            return result;
        }
    }
}
