using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Xml.Linq;

namespace fbctl.Apis
{
    internal class FlashBladeApi
    {
        internal const string HttpAuthorizationHeaderName = "Authorization";
        internal const string HttpJsonMediaType = "application/json";
        internal const string ApiVersion = "2.12";

        internal const string ObjectStoreAccountsMethod = "object-store-accounts";
        internal const string BucketsMethod = "buckets";
        internal const string BucketAccessPoliciesMethod = "buckets/bucket-access-policies";
        internal const string LifecycleRulesMethod = "lifecycle-rules";
        internal const string ObjectStoreUsersMethod = "object-store-users";
        internal const string ObjectStoreAccessPolicies = "object-store-users/object-store-access-policies";
        internal const string ObjectStoreAccessKeysMethod = "object-store-access-keys";
        internal const string ObjectStoreRemoteCredentialsMethod = "object-store-remote-credentials";
        internal const string BucketReplicaLinksMethod = "bucket-replica-links";

        internal string IpFqdn { get; init; }
        internal bool Insecure { get; init; }
        internal string? AccessToken { get; set; }

        internal FlashBladeApi(string ipFqdn, bool insecure = true)
        {
            IpFqdn = ipFqdn;
            Insecure = insecure;
        }

        private HttpClient CreateHttpClient()
        {
            if (Insecure)
            {
                var httpClientHandler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) =>
                    {
                        return true;
                    }
                };

                return new HttpClient(httpClientHandler);
            }

            return new HttpClient();
        }

        private HttpClient CreateAuthHttpClient()
        {
            if (string.IsNullOrWhiteSpace(AccessToken))
            {
                throw new InvalidOperationException("Login required before using this method");
            }

            HttpClient client;

            if (Insecure)
            {
                var httpClientHandler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) =>
                    {
                        return true;
                    }
                };

                client = new HttpClient(httpClientHandler);
                client.DefaultRequestHeaders.Add(HttpAuthorizationHeaderName, AccessToken);

                return client;
            }

            client = new HttpClient();
            client.DefaultRequestHeaders.Add(HttpAuthorizationHeaderName, AccessToken);

            return client;
        }

        private Uri CreateApiUri(string apiMethod, Dictionary<string, string>? queryParameters = null)
        {
            var builder = new UriBuilder($"https://{IpFqdn}/api/{ApiVersion}/{apiMethod}");

            if (queryParameters != null)
            {
                var query = HttpUtility.ParseQueryString(builder.Query);

                foreach (var parameter in queryParameters)
                    query[parameter.Key] = parameter.Value;

                builder.Query = query.ToString();
            }

            return builder.Uri;
        }

        internal async Task<bool> Login(string clientId, string keyId, string issuer, string username, string privateKeyPath)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(privateKeyPath));

            var key = new RsaSecurityKey(rsa)
            {
                KeyId = keyId
            };
            var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: clientId,
                claims: new[] { new Claim(JwtRegisteredClaimNames.Sub, username) },
                expires: DateTime.Now.AddMinutes(60),
                signingCredentials: creds);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(token);

            var content = new FormUrlEncodedContent
                (
                    new Dictionary<string, string>()
                    {
                        { "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange" },
                        { "subject_token" , encodedJwt },
                        { "subject_token_type", "urn:ietf:params:oauth:token-type:jwt" }
                    }
                );

            var httpClient = CreateHttpClient();

            var response = await httpClient.PostAsync($"https://{IpFqdn}/oauth2/1.0/token", content);

            if (response.IsSuccessStatusCode)
            {
                var responseJson = JObject.Parse(await response.Content.ReadAsStringAsync());
                AccessToken = "Bearer " + responseJson["access_token"];
            }

            return response.IsSuccessStatusCode;
        }

        internal async Task<List<Version>?> GetApiVersions()
        {
            var httpClient = CreateHttpClient();
            var response = await httpClient.GetAsync($"https://{IpFqdn}/api/api_version");

            if (response.IsSuccessStatusCode)
            {
                var responseJson = JObject.Parse(await response.Content.ReadAsStringAsync());
                return responseJson["versions"]!.Select(p => new Version(p.ToString())).ToList();
            }

            return null;
        }

        internal async Task<bool> IsAccountExists(string account)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "names", account }
            };

            var response = await httpClient.GetAsync(CreateApiUri(ObjectStoreAccountsMethod, queryParameters));
            return response.IsSuccessStatusCode;
        }

        internal async Task<bool> CreateAccount(string account)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "names", account }
            };

            var response = await httpClient.PostAsync(CreateApiUri(ObjectStoreAccountsMethod, queryParameters), null);
            return response.IsSuccessStatusCode;
        }

        internal async Task<bool> IsBucketExists(string bucket)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "names", bucket }
            };

            var response = await httpClient.GetAsync(CreateApiUri(BucketsMethod, queryParameters));
            return response.IsSuccessStatusCode;
        }

        internal async Task<bool> EnablePublicAccessForAccount(string account)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "names", account }
            };

            dynamic content = new
            {
                public_access_config = new { block_public_access = "false", block_new_public_policies = "false" }
            };

            var response = await httpClient.PatchAsync(
                CreateApiUri(ObjectStoreAccountsMethod, queryParameters),
                new StringContent(JsonConvert.SerializeObject(content),
                new MediaTypeHeaderValue(HttpJsonMediaType)));

            return response.IsSuccessStatusCode;
        }

        internal async Task<bool> CreateBucket(string account, string bucket)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "names", bucket }
            };

            dynamic content = new
            {
                account = new { name = account }
            };

            var response = await httpClient.PostAsync(
                CreateApiUri(BucketsMethod, queryParameters),
                new StringContent(JsonConvert.SerializeObject(content),
                new MediaTypeHeaderValue(HttpJsonMediaType)));

            return response.IsSuccessStatusCode;
        }

        internal async Task<bool> EnableVersioningForBucket(string bucket)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "names", bucket }
            };

            dynamic content = new
            {
                versioning = "enabled"
            };

            var response = await httpClient.PatchAsync(
                CreateApiUri(BucketsMethod, queryParameters),
                new StringContent(JsonConvert.SerializeObject(content),
                new MediaTypeHeaderValue(HttpJsonMediaType)));

            return response.IsSuccessStatusCode;
        }

        internal async Task<bool> EnablePublicAccessForBucket(string bucket)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "names", bucket }
            };

            dynamic content = new
            {
                public_access_config = new { block_public_access = "false", block_new_public_policies = "false" }
            };

            var response = await httpClient.PatchAsync(
                CreateApiUri(BucketsMethod, queryParameters),
                new StringContent(JsonConvert.SerializeObject(content),
                new MediaTypeHeaderValue(HttpJsonMediaType)));

            return response.IsSuccessStatusCode;
        }

        internal async Task<bool> CreatePublicBucketAccessPolicyForBucket(string bucket)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "bucket_names", bucket }
            };

            dynamic content = new
            {
                rules = new[] { new { name = "default", actions = new[] { "s3:GetObject" }, resources = new[] { $"{bucket}/*" }, principals = new { all = "true" } } }
            };

            var response = await httpClient.PostAsync(
                CreateApiUri(BucketAccessPoliciesMethod, queryParameters),
                new StringContent(JsonConvert.SerializeObject(content),
                new MediaTypeHeaderValue(HttpJsonMediaType)));

            return response.IsSuccessStatusCode;
        }

        internal async Task<bool> CreateLifecycleRuleForBucket(string bucket, int days)
        {
            var httpClient = CreateAuthHttpClient();

            dynamic content = new
            {
                bucket = new { name = bucket },
                keep_previous_version_for = days * 86400000,
            };

            var response = await httpClient.PostAsync(
                CreateApiUri(LifecycleRulesMethod),
                new StringContent(JsonConvert.SerializeObject(content),
                new MediaTypeHeaderValue(HttpJsonMediaType)));

            return response.IsSuccessStatusCode;
        }

        internal async Task<bool> IsUserExists(string account, string user)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "names", account + "/" + user }
            };

            var response = await httpClient.GetAsync(CreateApiUri(ObjectStoreUsersMethod, queryParameters));

            return response.IsSuccessStatusCode;
        }

        internal async Task<bool> CreateUser(string account, string user, bool fullAccess)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "names", account + "/" + user },
                { "full_access", fullAccess.ToString().ToLower() }
            };

            var response = await httpClient.PostAsync(CreateApiUri(ObjectStoreUsersMethod, queryParameters), null);

            return response.IsSuccessStatusCode;
        }

        internal async Task<Tuple<string, string>?> CreateAccessKeyForUser(string account, string user)
        {
            var httpClient = CreateAuthHttpClient();

            dynamic content = new
            {
                user = new { name = account + "/" + user }
            };

            var response = await httpClient.PostAsync(
                CreateApiUri(ObjectStoreAccessKeysMethod),
                new StringContent(JsonConvert.SerializeObject(content),
                new MediaTypeHeaderValue(HttpJsonMediaType)));

            if (response.IsSuccessStatusCode)
            {
                var responseJson = JObject.Parse(await response.Content.ReadAsStringAsync());

                var accessKeyId = responseJson["items"]!.First()["name"]!.ToString();
                var secretAccessKey = responseJson["items"]!.First()["secret_access_key"]!.ToString();

                return new Tuple<string, string>(accessKeyId, secretAccessKey);
            }

            return null;
        }

        internal async Task<bool> ImportAccessKeyForUser(string account, string user, string accessKeyId, string secretAccessKey)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "names", accessKeyId }
            };

            dynamic content = new
            {
                user = new { name = account + "/" + user },
                secret_access_key = secretAccessKey
            };

            var response = await httpClient.PostAsync(
                CreateApiUri(ObjectStoreAccessKeysMethod, queryParameters),
                new StringContent(JsonConvert.SerializeObject(content),
                new MediaTypeHeaderValue(HttpJsonMediaType)));

            return response.IsSuccessStatusCode;
        }

        internal async Task<bool> SetAccessPoliciesForUser(string account, string user, string accessPolicies)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "member_names", account + "/" + user },
                { "policy_names", accessPolicies  }
            };

            var response = await httpClient.PostAsync(CreateApiUri(ObjectStoreAccessPolicies, queryParameters), null);

            return response.IsSuccessStatusCode;
        }

        internal async Task<bool> IsRemoteCredentialExists(string remoteFlashBlade, string user)
        {
            var httpClient = CreateAuthHttpClient();

            var name = remoteFlashBlade + "/" + user;
            var queryParameters = new Dictionary<string, string>()
            {
                { "names", name }
            };

            var response = await httpClient.GetAsync(CreateApiUri(ObjectStoreRemoteCredentialsMethod, queryParameters));

            return response.IsSuccessStatusCode;
        }

        internal async Task<string?> CreateRemoteCredential(string remoteFlashBlade, string user, string accessKeyId, string secretAccessKey)
        {
            var httpClient = CreateAuthHttpClient();

            var name = remoteFlashBlade + "/" + user;
            var queryParameters = new Dictionary<string, string>()
            {
                { "names", name }
            };

            dynamic content = new
            {
                access_key_id = accessKeyId,
                secret_access_key = secretAccessKey
            };

            var response = await httpClient.PostAsync(
                CreateApiUri(ObjectStoreRemoteCredentialsMethod, queryParameters),
                new StringContent(JsonConvert.SerializeObject(content),
                new MediaTypeHeaderValue(HttpJsonMediaType)));

            if (response.IsSuccessStatusCode)
                return name;

            return null;
        }

        internal async Task<bool> CreateBucketReplicaLink(string bucket, string remoteCredential)
        {
            var httpClient = CreateAuthHttpClient();

            var queryParameters = new Dictionary<string, string>()
            {
                { "local_bucket_names", bucket },
                { "remote_bucket_names", bucket },
                { "remote_credentials_names", remoteCredential }
            };

            var response = await httpClient.PostAsync(CreateApiUri(BucketReplicaLinksMethod, queryParameters), null);
            return response.IsSuccessStatusCode;
        }

    }
}
