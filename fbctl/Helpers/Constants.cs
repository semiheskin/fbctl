using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fbctl.Helpers
{
    public static class Constants
    {
        public const string AppSettingsFlashBladesSectionName = "flashblades";
        public const string AppSettingsFlashBladeManagementIpFqdnKey = "management_ip_fqdn";
        public const string AppSettingsFlashBladeDataIpFqdnKey = "data_ip_fqdn";
        public const string AppSettingsFlashBladeClientIdKey = "clientid";
        public const string AppSettingsFlashBladeKeyIdKey = "keyid";
        public const string AppSettingsFlashBladeIssuerKey = "issuer";
        public const string AppSettingsFlashBladeUsernameKey = "username";
        public const string AppSettingsFlashBladePrivateKeyPathKey = "privatekeypath";

        public static readonly string[] UserPolicies =
        [
            "pure:policy/bucket-configure",
            "pure:policy/bucket-create",
            "pure:policy/bucket-delete",
            "pure:policy/bucket-info",
            "pure:policy/bucket-list",
            "pure:policy/object-delete",
            "pure:policy/object-list",
            "pure:policy/object-lock",
            "pure:policy/object-lock-bypass-governance",
            "pure:policy/object-read",
            "pure:policy/object-write",
            "pure:policy/version-delete"
        ];
    }
}
