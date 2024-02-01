using fbctl.Apis;
using fbctl.Helpers;
using Microsoft.Extensions.Configuration;
using Spectre.Console;
using Spectre.Console.Cli;
using System.ComponentModel;

namespace fbctl.Commands
{
    public class BiDirRepCreateCommand : AsyncCommand<BiDirRepCreateCommand.Settings>
    {
        public class Settings : CommandSettings
        {
            [Description("Name of the first FlashBlade. Must match the name in the appsettings.json")]
            [CommandArgument(0, "<array1>")]
            public string? Array1 { get; init; }

            [Description("Name of the second FlashBlade. Must match the name in the appsettings.json")]
            [CommandArgument(1, "<array2>")]
            public string? Array2 { get; init; }

            [Description("Name of the account to be used")]
            [CommandOption("--account")]
            public string? Account { get; init; }

            [Description("Flag for new account creation")]
            [CommandOption("--create-account")]
            public bool? CreateAccount { get; init; }

            [Description("Name of the new user to be created")]
            [CommandOption("--new-user")]
            public string? NewUser { get; init; }

            [Description("Command seperated list of policies for the new user")]
            [CommandOption("--new-user-policies")]
            public string? NewUserPolicies { get; init; }

            public string[]? NewUserPoliciesList
            {
                get
                {
                    if (NewUserPolicies is not null)
                    {
                        return NewUserPolicies.Split(',', StringSplitOptions.RemoveEmptyEntries & StringSplitOptions.TrimEntries);
                    }

                    return null;
                }
            }

            [Description("Name of the replication user to be used")]
            [CommandOption("--replication-user")]
            public string? ReplicationUser { get; init; }

            [Description("Flag for new replication user creation")]
            [CommandOption("--create-replication-user")]
            public bool? CreateReplicationUser { get; init; }

            [Description("Name of the bucket to be created")]
            [CommandOption("--bucket")]
            public string? Bucket { get; init; }

            [Description("Flag for setting public access for the bucket")]
            [CommandOption("--public-bucket")]
            public bool? PublicBucket { get; init; }

            [Description("Retention duration in days for object versioning")]
            [CommandOption("--retention")]
            [DefaultValue(7)]
            public int Retention { get; init; }
        }

        public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
        {
            if (context.Data is not IConfigurationRoot appsettings)
                return 1;

            var fb1 = FlashBladeSettingsHelper.ConvertToSettings(appsettings.GetSection(Constants.AppSettingsFlashBladesSectionName), settings.Array1!);
            var fb2 = FlashBladeSettingsHelper.ConvertToSettings(appsettings.GetSection(Constants.AppSettingsFlashBladesSectionName), settings.Array2!);


            AnsiConsole.Write("\nRunning pre-checks");
            if (!FlashBladeSettingsHelper.CheckMagementApiNetworkAccess(fb1, fb2)) return 1;
            if (!FlashBladeSettingsHelper.CheckManagementApiVersion(fb1, fb2)) return 1;
            if (!FlashBladeSettingsHelper.CheckLogin(fb1, fb2)) return 1;
            AnsiConsole.WriteLine("\nPre-checks finished");

            var flashBlades = new Tuple<FlashBladeSettings, FlashBladeApi>[2];

            flashBlades[0] = new Tuple<FlashBladeSettings, FlashBladeApi>(fb1, new FlashBladeApi(fb1.ManagementIpFqdn!));
            flashBlades[1] = new Tuple<FlashBladeSettings, FlashBladeApi>(fb2, new FlashBladeApi(fb2.ManagementIpFqdn!));

            //Login to both FlashBlades
            foreach (var fb in flashBlades)
            {
                if (await fb.Item2.Login(fb.Item1.ClientId!, fb.Item1.KeyId!, fb.Item1.Issuer!, fb.Item1.Username!, fb.Item1.PrivateKeyPath!))
                {
                    AnsiConsole.Markup($"\nLogged into FlashBalde \'{fb.Item1.Name}\' [green]successfully[/]");
                }
                else
                {
                    AnsiConsole.Markup($"\nLogin [red]failed[/] for FlashBlade \'{fb.Item1.Name}\'");
                    return 1;
                }
            }

            //Validate --create-account flag
            foreach (var fb in flashBlades)
            {
                var isAccountExists = await fb.Item2.IsAccountExists(settings.Account!);

                if (isAccountExists &&
                    settings.CreateAccount.HasValue &&
                    settings.CreateAccount.Value)
                {
                    AnsiConsole.Markup($"\nAccount \'{settings.Account}\' already exists on FlashBlade \'{fb.Item1.Name}\'" +
                        $"\nDrop --create-account option to use existing account");

                    return 1;
                }

                if (!isAccountExists &&
                    (!settings.CreateAccount.HasValue || !settings.CreateAccount.Value))
                {
                    AnsiConsole.Markup($"\nAccount \'{settings.Account}\' doesn't exists on FlashBlade \'{fb.Item1.Name}\'" +
                        $"\nSet --create-account option to create new account");

                    return 1;
                }
            }

            var isReplicationUserExists = false;
            //if it is a new account, don't need to validate user and replication user
            if (!settings.CreateAccount.HasValue || !settings.CreateAccount.Value)
            {
                //Validate --new-user, --create-replicaiton-user
                foreach (var fb in flashBlades)
                {
                    //Validate --create-user
                    var isUserExists = await fb.Item2.IsUserExists(settings.Account!, settings.NewUser!);

                    if (isUserExists && !string.IsNullOrWhiteSpace(settings.NewUser))
                    {
                        AnsiConsole.Markup($"\nUser \'{settings.Account + "/" + settings.NewUser}\' already exists on FlashBlade \'{fb.Item1.Name}\'" +
                            $"\nDrop --new-user option or provide a user that doesn't exists");

                        return 1;
                    }

                    //Validate --create-replicaiton-user
                    isReplicationUserExists = await fb.Item2.IsUserExists(settings.Account!, settings.ReplicationUser!);

                    if (isReplicationUserExists &&
                        settings.CreateReplicationUser.HasValue &&
                        settings.CreateReplicationUser.Value)
                    {
                        AnsiConsole.Markup($"\nReplication user \'{settings.Account + "/" + settings.ReplicationUser}\' already exists on FlashBlade \' {fb.Item1.Name} \'" +
                            $"\nDrop --create-replicaiton-user option to use existing replication user");

                        return 1;
                    }

                    if (!isReplicationUserExists &&
                        (!settings.CreateReplicationUser.HasValue || !settings.CreateReplicationUser.Value))
                    {
                        AnsiConsole.Markup($"\nUser \'{settings.Account + "/" + settings.ReplicationUser}\' doesn't exists on FlashBlade \'{fb.Item1.Name}\'" +
                            $"\nSet --create-replicaiton-user option to create new user");

                        return 1;
                    }
                }

            }

            //Remote credentials are in arrayname/username format and shoud be unique in array scope
            //Even if the replication user is not exits under the account, we shoud check if there is any remote credential with the same name
            if (!isReplicationUserExists)
            {
                if (await flashBlades[0].Item2.IsRemoteCredentialExists(flashBlades[1].Item1.Name!, settings.ReplicationUser!))
                {
                    AnsiConsole.Markup($"\nRemote credential with name \'{flashBlades[1].Item1.Name! + "/" + settings.ReplicationUser!}\' already exists on FlashBalde \'{flashBlades[0].Item1.Name}\'" +
                        $"\nTry a different name for the replicaiton user");

                    return 1;
                }

                if (await flashBlades[1].Item2.IsRemoteCredentialExists(flashBlades[0].Item1.Name!, settings.ReplicationUser!))
                {
                    AnsiConsole.Markup($"\nRemote credential with name \'{flashBlades[0].Item1.Name! + "/" + settings.ReplicationUser!}\' already exists on FlashBalde \'{flashBlades[1].Item1.Name}\'" +
                        $"\nTry a different name for the replicaiton user");

                    return 1;
                }
            }

            //Validate --bucket. Bucket names must be unique in array scope
            foreach (var fb in flashBlades)
            {
                if (await fb.Item2.IsBucketExists(settings.Bucket!))
                {
                    AnsiConsole.Markup($"\nBucket \'{settings.Bucket}\' already exists on FlashBlade \'{fb.Item1.Name}\'" +
                        $"\nExisting buckets are not supported and bucket names must be unique in array scope");

                    return 1;
                }
            }

            //Validate remote credentials if replication user is already exists
            if (isReplicationUserExists)
            {
                if (!await flashBlades[0].Item2.IsRemoteCredentialExists(flashBlades[1].Item1.Name!, settings.ReplicationUser!))
                {
                    AnsiConsole.Markup($"\nRemote credential doesn't exits for the replication user \'{settings.ReplicationUser}\' supplied on FlashBlade \'{flashBlades[1].Item1.Name}\'" +
                        $"\nCreate remote credential manually or use \'--create-replication-user\' option to create a new one");

                    return 1;
                }

                if (!await flashBlades[1].Item2.IsRemoteCredentialExists(flashBlades[0].Item1.Name!, settings.ReplicationUser!))
                {
                    AnsiConsole.Markup($"\nRemote credential doesn't exits for the replication user \'{settings.ReplicationUser}\' supplied on FlashBlade \'{flashBlades[0].Item1.Name}\'" +
                        $"\nCreate remote credential manually or use --create-replication-user option to create a new one");

                    return 1;
                }
            }

            //Create account if needed on both FlashBlades
            if (settings.CreateAccount.HasValue && settings.CreateAccount.Value)
            {
                foreach (var fb in flashBlades)
                {
                    if (await fb.Item2.CreateAccount(settings.Account!))
                    {
                        AnsiConsole.Markup($"\nAccount \'{settings.Account}\' created on FlashBlade \'{fb.Item1.Name}\' [green]successfully[/]");
                    }
                    else
                    {
                        AnsiConsole.Markup($"\nAccount creation for the account \'{settings.Account}\' [red]failed[/] for FlashBlade \'{fb.Item1.Name}\'");
                        return 1;
                    }
                }
            }

            //Create user if needed on both FlashBlades
            if (!string.IsNullOrWhiteSpace(settings.NewUser))
            {
                //Create users
                foreach (var fb in flashBlades)
                {
                    var isNewUserPoliciesSet = !string.IsNullOrWhiteSpace(settings.NewUserPolicies);

                    //if custom user policies is not set, user will be created with full-access permission
                    if (await fb.Item2.CreateUser(settings.Account!, settings.NewUser!, !isNewUserPoliciesSet))
                    {
                        AnsiConsole.Markup($"\nUser \'{settings.NewUser}\' created on FlashBlade \'{fb.Item1.Name}\' [green]successfully[/]");
                    }
                    else
                    {
                        AnsiConsole.Markup($"\nUser creation for the user \'{settings.NewUser}\' [red]failed[/] on FlashBlade \'{fb.Item1.Name}\'");
                        return 1;
                    }

                    //if custom user policies are set, set these policies for the user
                    //Policies must be added one by one, this is enforced by the FlashBlade Api
                    if (isNewUserPoliciesSet)
                    {
                        foreach (var policyToAdd in settings.NewUserPoliciesList!)
                        {
                            if (await fb.Item2.SetAccessPoliciesForUser(settings.Account!, settings.NewUser!, policyToAdd))
                            {
                                AnsiConsole.Markup($"\nAccess policy \'{policyToAdd}\' is set for the user \'{settings.NewUser}\' on FlashBlade \'{fb.Item1.Name}\' [green]successfully[/]");
                            }
                            else
                            {
                                AnsiConsole.Markup($"\nSetting up access policies \'{settings.NewUserPolicies}\' for the user \'{settings.NewUser}\' [red]failed[/] on FlashBlade \'{fb.Item1.Name}\'");
                                return 1;
                            }
                        }
                    }

                }

                //Create access key on FlashBlade 1
                var accessKeyResult = await flashBlades[0].Item2.CreateAccessKeyForUser(settings.Account!, settings.NewUser!);
                if (accessKeyResult is null)
                {
                    AnsiConsole.Markup($"\nAccess key creation for the user \'{settings.NewUser}\' [red]failed[/] on FlashBlade \'{flashBlades[0].Item1.Name}\'");
                    return 1;
                }
                else
                {
                    AnsiConsole.Markup($"\nAccess Key \'{accessKeyResult.Item1}\' created on FlashBlade \'{flashBlades[0].Item1.Name}\' [green]successfully[/]");
                }

                //Import access key to FlashBlade 2
                if (await flashBlades[1].Item2.ImportAccessKeyForUser(settings.Account!, settings.NewUser!, accessKeyResult.Item1, accessKeyResult.Item2))
                {
                    AnsiConsole.Markup($"\nAccess Key \'{accessKeyResult.Item1}\' imported to FlashBlade \'{flashBlades[1].Item1.Name}\' [green]successfully[/]");
                }
                else
                {
                    AnsiConsole.Markup($"\nAccess key creation for the user \'{settings.NewUser}\' [red]failed[/] on FlashBlade {flashBlades[1].Item1.Name}");
                    return 1;
                }

                AnsiConsole.Markup($"\n\nUser: {settings.NewUser}" +
                    $"\nAccess Key ID: {accessKeyResult.Item1}" +
                    $"\nSecret Access Key: {accessKeyResult.Item2}" +
                    $"\nSave these parameters for further use\n");

            }

            Tuple<string, string>? replicationUserAccessKey = null;
            //Create replication user if needed on both FlashBlades
            if (settings.CreateReplicationUser.HasValue && settings.CreateReplicationUser.Value)
            {
                //Create replication users
                foreach (var fb in flashBlades)
                {
                    //Replication user needs full access
                    if (await fb.Item2.CreateUser(settings.Account!, settings.ReplicationUser!, true))
                    {
                        AnsiConsole.Markup($"\nUser \'{settings.ReplicationUser}\' created on FlashBlade \'{fb.Item1.Name}\' [green]successfully[/]");
                    }
                    else
                    {
                        AnsiConsole.Markup($"\nUser creation for the replication user \'{settings.ReplicationUser}\' [red]failed[/] on FlashBlade \'{fb.Item1.Name}\'");
                        return 1;
                    }
                }

                //Create access key on FlashBlade 1
                replicationUserAccessKey = await flashBlades[0].Item2.CreateAccessKeyForUser(settings.Account!, settings.ReplicationUser!);
                if (replicationUserAccessKey is null)
                {
                    AnsiConsole.Markup($"\nAccess key creation for the replication user \'{settings.ReplicationUser}\' [red]failed[/] on FlashBlade \'{flashBlades[0].Item1.Name}\'");
                    return 1;
                }
                else
                {
                    AnsiConsole.Markup($"\nAccess Key \'{replicationUserAccessKey.Item1}\' created on FlashBlade \'{flashBlades[0].Item1.Name}\' [green]successfully[/]");
                }

                //Import access key to FlashBlade 2
                if (await flashBlades[1].Item2.ImportAccessKeyForUser(settings.Account!, settings.ReplicationUser!, replicationUserAccessKey.Item1, replicationUserAccessKey.Item2))
                {
                    AnsiConsole.Markup($"\nAccess Key \'{replicationUserAccessKey.Item1}\' imported to FlashBlade \'{flashBlades[1].Item1.Name}\' [green]successfully[/]");
                }
                else
                {
                    AnsiConsole.Markup($"\nAccess key creation for the replication user \'{settings.ReplicationUser}\' [red]failed[/] on FlashBlade \'{flashBlades[1].Item1.Name}\'");
                    return 1;
                }

                AnsiConsole.Markup($"\n\nReplication User: {settings.ReplicationUser}" +
                    $"\nAccess Key ID: {replicationUserAccessKey.Item1}" +
                    $"\nSecret Access Key: {replicationUserAccessKey.Item2}" +
                    $"\nSave these parameters for further use\n");

            }

            //Create bucket and configure bucket
            foreach (var fb in flashBlades)
            {
                if (await fb.Item2.CreateBucket(settings.Account!, settings.Bucket!))
                {
                    AnsiConsole.Markup($"\nBucket \'{settings.Bucket}\' created on FlashBlade \'{fb.Item1.Name}\' [green]successfully[/]");
                }
                else
                {
                    AnsiConsole.Markup($"\nBucket creation for the bucket \'{settings.Bucket}\' [red]failed[/] on FlashBlade \'{fb.Item1.Name}\'");
                    return 1;
                }

                if (await fb.Item2.EnableVersioningForBucket(settings.Bucket!))
                {
                    AnsiConsole.Markup($"\nVersioning enabled for bucket \'{settings.Bucket}\' on FlashBlade \'{fb.Item1.Name}\' [green]successfully[/]");
                }
                else
                {
                    AnsiConsole.Markup($"\nEnable versioning for the bucket \'{settings.Bucket}\' [red]failed[/] on FlashBlade \'{fb.Item1.Name}\'");
                    return 1;
                }

                if (await fb.Item2.CreateLifecycleRuleForBucket(settings.Bucket!, settings.Retention))
                {
                    AnsiConsole.Markup($"\nLifecycle rule for Bucket \'{settings.Bucket}\' on FlashBlade \'{fb.Item1.Name}\' created [green]successfully[/]");
                }
                else
                {
                    AnsiConsole.Markup($"\nCreating lifecycle rule for the bucket \'{settings.Bucket}\' [red]failed[/] on FlashBlade \'{fb.Item1.Name}\'");
                    return 1;
                }

                //make buckets public
                if (settings.PublicBucket.HasValue && settings.PublicBucket.Value)
                {
                    if (await fb.Item2.EnablePublicAccessForAccount(settings.Account!) &&
                        await fb.Item2.EnablePublicAccessForBucket(settings.Bucket!) &&
                        await fb.Item2.CreatePublicBucketAccessPolicyForBucket(settings.Bucket!))
                    {
                        AnsiConsole.Markup($"\nPublic access enabled for bucket \'{settings.Bucket}\' on FlashBlade \'{fb.Item1.Name}\' [green]successfully[/]");
                    }
                    else
                    {
                        AnsiConsole.Markup($"\nEnabling public access for the bucket \'{settings.Bucket}\' [red]failed[/] on FlashBlade \'{fb.Item1.Name}\'" +
                            $"\nPlease enable public access manually from the FlashBlade");

                        //contiunue process, public access is not mandatory for replication
                    }
                }
            }

            //create remote credentails for the replication user
            if (!isReplicationUserExists && replicationUserAccessKey is not null)
            {
                if (string.IsNullOrWhiteSpace(
                    await flashBlades[0].Item2.CreateRemoteCredential(
                        flashBlades[1].Item1.Name!,
                        settings.ReplicationUser!,
                        replicationUserAccessKey.Item1,
                        replicationUserAccessKey.Item2)
                    ))
                {
                    AnsiConsole.Markup($"\nCreating remote credential for the user \'{settings.ReplicationUser}\' [red]failed[/] on FlashBlade \'{flashBlades[0].Item1.Name}\'");
                    return 1;
                }
                else
                {
                    AnsiConsole.Markup($"\nRemote credential for the user \'{settings.ReplicationUser}\' on FlashBlade \'{flashBlades[0].Item1.Name}\' created [green]successfully[/]");
                }

                if (string.IsNullOrWhiteSpace(
                    await flashBlades[1].Item2.CreateRemoteCredential(
                        flashBlades[0].Item1.Name!,
                        settings.ReplicationUser!,
                        replicationUserAccessKey.Item1,
                        replicationUserAccessKey.Item2)
                    ))
                {
                    AnsiConsole.Markup($"\nCreating remote credential for the user \'{settings.ReplicationUser}\' [red]failed[/] on FlashBlade \'{flashBlades[1].Item1.Name}\'");
                    return 1;
                }
                else
                {
                    AnsiConsole.Markup($"\nRemote credential for the user \'{settings.ReplicationUser}\' on FlashBlade \'{flashBlades[1].Item1.Name}\' created [green]successfully[/]");
                }
            }

            //Create bucket replica links
            if (await flashBlades[0].Item2.CreateBucketReplicaLink(settings.Bucket!, flashBlades[1].Item1.Name + "/" + settings.ReplicationUser))
            {
                AnsiConsole.Markup($"\nBucket replica link from \'{flashBlades[0].Item1.Name}\' to \'{flashBlades[1].Item1.Name}\' for bucket \'{settings.Bucket}\' created [green]successfully[/]");
            }
            else
            {
                AnsiConsole.Markup($"\nBucket replica link creation from \'{flashBlades[0].Item1.Name}\' to \'{flashBlades[1].Item1.Name}\' for bucket \'{settings.Bucket}\' [red]failed[/]");
                return 1;
            }

            if (await flashBlades[1].Item2.CreateBucketReplicaLink(settings.Bucket!, flashBlades[0].Item1.Name + "/" + settings.ReplicationUser))
            {
                AnsiConsole.Markup($"\nBucket replica link from \'{flashBlades[1].Item1.Name}\' to \'{flashBlades[0].Item1.Name}\' for bucket \'{settings.Bucket}\' created [green]successfully[/]");
            }
            else
            {
                AnsiConsole.Markup($"\nBucket replica link creation from \'{flashBlades[1].Item1.Name}\' to \'{flashBlades[0].Item1.Name}\' for bucket \'{settings.Bucket}\' [red]failed[/]");
                return 1;
            }

            AnsiConsole.WriteLine();

            return 0;
        }

        public override ValidationResult Validate(CommandContext context, Settings settings)
        {

            if (context.Data is not IConfigurationRoot appsettings)
                return ValidationResult.Error("AppSettings file could not be found");

            if (!FlashBladeSettingsHelper.ValidateSettings(appsettings, out ValidationResult result, settings.Array1!, settings.Array2!))
                return result;

            if (settings.Account is null)
                return ValidationResult.Error("--account option must be specified");

            if (settings.ReplicationUser is null)
                return ValidationResult.Error("--replication-user option must be specified");

            if (settings.CreateAccount is not null && settings.CreateReplicationUser is null)
                return ValidationResult.Error("when --create-account is set new replication user must be created with --create-replication-user option");

            if (settings.Bucket is null)
                return ValidationResult.Error("--bucket option must be specified");

            if (settings.NewUser is null && settings.NewUserPolicies is not null)
                return ValidationResult.Error("--new-user-polices option must be used when --new-user option has been specified");

            if (settings.NewUserPolicies is not null && settings.NewUserPoliciesList!.Length != settings.NewUserPoliciesList!.Intersect(Constants.UserPolicies).Count())
                return ValidationResult.Error("--new-user-policies option must be a comma(,) seperated list of valid policies");

            return base.Validate(context, settings);
        }
    }
}
