using fbctl.Apis;
using Microsoft.Extensions.Configuration;
using Spectre.Console;
using System.Net.Sockets;

namespace fbctl.Helpers
{
    internal static class FlashBladeSettingsHelper
    {
        internal static FlashBladeSettings ConvertToSettings(IConfigurationSection configSection, string flashBlade)
        {
            return configSection.GetChildren().Where(p => p.Key == flashBlade).Select(p => new FlashBladeSettings()
            {
                Name = p.Key,
                ClientId = p[Constants.AppSettingsFlashBladeClientIdKey],
                ManagementIpFqdn = p[Constants.AppSettingsFlashBladeManagementIpFqdnKey],
                Issuer = p[Constants.AppSettingsFlashBladeIssuerKey],
                KeyId = p[Constants.AppSettingsFlashBladeKeyIdKey],
                PrivateKeyPath = p[Constants.AppSettingsFlashBladePrivateKeyPathKey],
                Username = p[Constants.AppSettingsFlashBladeUsernameKey]
            }).First();
        }

        internal static bool ValidateSettings(IConfigurationRoot configurationRoot, out ValidationResult result, params string[] flashBladeNames)
        {

            var flashbadesSection = configurationRoot.GetSection(Constants.AppSettingsFlashBladesSectionName);

            foreach (var name in flashBladeNames)
            {
                var arraySettings = flashbadesSection.GetChildren().Where(p => p.Key == name).FirstOrDefault();
                if (arraySettings == null)
                {
                    result = ValidationResult.Error($"Array settings for the array {name} could not be found in the AppSettings");
                    return false;
                }


                if (string.IsNullOrWhiteSpace(arraySettings[Constants.AppSettingsFlashBladeManagementIpFqdnKey]))
                {
                    result = ValidationResult.Error($"{Constants.AppSettingsFlashBladeManagementIpFqdnKey} is missing in the AppSettings for the array {name}");
                    return false;
                }
                if (string.IsNullOrWhiteSpace(arraySettings[Constants.AppSettingsFlashBladeClientIdKey]))
                {
                    result = ValidationResult.Error($"{Constants.AppSettingsFlashBladeClientIdKey} is missing in the AppSettings for the array {name}");
                    return false;
                }
                if (string.IsNullOrWhiteSpace(arraySettings[Constants.AppSettingsFlashBladeKeyIdKey]))
                {
                    result = ValidationResult.Error($"{Constants.AppSettingsFlashBladeKeyIdKey} is missing in the AppSettings for the array {name}");
                    return false;
                }
                if (string.IsNullOrWhiteSpace(arraySettings[Constants.AppSettingsFlashBladeIssuerKey]))
                {
                    result = ValidationResult.Error($"{Constants.AppSettingsFlashBladeIssuerKey} is missing in the AppSettings for the array {name}");
                    return false;
                }
                if (string.IsNullOrWhiteSpace(arraySettings[Constants.AppSettingsFlashBladeUsernameKey]))
                {
                    result = ValidationResult.Error($"{Constants.AppSettingsFlashBladeUsernameKey} is missing in the AppSettings for the array {name}");
                    return false;
                }
                if (string.IsNullOrWhiteSpace(arraySettings[Constants.AppSettingsFlashBladePrivateKeyPathKey]))
                {
                    result = ValidationResult.Error($"{Constants.AppSettingsFlashBladePrivateKeyPathKey} is missing in the AppSettings for the array {name}");
                    return false;
                }
                if (!Path.Exists(arraySettings[Constants.AppSettingsFlashBladePrivateKeyPathKey]))
                {
                    result = ValidationResult.Error($"Private key file for the {name} could not be found in the path {arraySettings[Constants.AppSettingsFlashBladePrivateKeyPathKey]}");
                    return false;
                }
            }

            result = ValidationResult.Success();
            return true;
        }

        internal static bool CheckMagementApiNetworkAccess(params FlashBladeSettings[] flashBlades)
        {
            foreach (var fb in flashBlades)
            {
                try
                {
                    var tcpClient = new TcpClient();
                    AnsiConsole.Write($"\nTesting API network access for {fb.Name} - ");
                    tcpClient.Connect(fb.ManagementIpFqdn!, 443);
                    AnsiConsole.Markup($"[green]Ok[/]");
                }
                catch
                {
                    AnsiConsole.Markup($"[red]Failed[/]");
                    return false;
                }
            }

            return true;
        }

        internal static bool CheckManagementApiVersion(params FlashBladeSettings[] flashBlades)
        {
            foreach (var fb in flashBlades)
            {
                var fb1Api = new FlashBladeApi(fb.ManagementIpFqdn!);

                AnsiConsole.Write($"\nTesting API version (min 2.12) for {fb.Name} - ");
                var result = fb1Api.GetApiVersions().Result;
                if (result == null || result.Count == 0)
                {
                    AnsiConsole.Markup($"[red]Failed[/]");
                    return false;
                }

                if (result.Max() >= new Version("2.12"))
                {
                    AnsiConsole.Markup($"[green]Ok[/]");
                }
                else
                {
                    AnsiConsole.Markup($"[red]Failed[/]");
                    return false;
                }
            }

            return true;
        }

        internal static bool CheckLogin(params FlashBladeSettings[] flashBlades)
        {
            foreach (var fb in flashBlades)
            {
                AnsiConsole.Write($"\nTesting API login for {fb.Name} - ");

                if (new FlashBladeApi(fb.ManagementIpFqdn!).Login(fb.ClientId!, fb.KeyId!, fb.Issuer!, fb.Username!, fb.PrivateKeyPath!).Result)
                {
                    AnsiConsole.Markup($"[green]Ok[/]");
                }
                else
                {
                    AnsiConsole.Markup($"[red]Failed[/]");
                    return false;
                }
            }

            return true;
        }
    }
}
