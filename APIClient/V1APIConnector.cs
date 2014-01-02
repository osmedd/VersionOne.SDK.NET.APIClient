using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;

namespace VersionOne.SDK.APIClient {

    public class V1APIConnector : V1CredsAPIConnector
    {
        /// <summary>
        /// Create a new VersionOne server connector.
        /// </summary>
        /// <param name="urlPrefix">The base URL of the server</param>
        /// <param name="username">Used for Basic authorization responses (and NTLM/Negotiate if integratedAuth=true)</param>
        /// <param name="password">Used for Basic authorization responses (and NTLM/Negotiate if integratedAuth=true)</param>
        /// <param name="integratedAuth">Whether to try NTLM/Negotiate auth.  If Username is provided, it and the password will be used for the exchange. Otherwise the implicit Windows identity will be used.</param>
        /// <param name="proxy">A proxy to use for HTTP connections.</param>
        /// <param name="storage">If provider, enables response to OAuth2 Bearer challenges.</param>
		public V1APIConnector(string urlPrefix, string username = null, string password = null, bool? integratedAuth = null, 
		                      ProxyProvider proxy = null, OAuth2Client.IStorage storage = null)
            : base(urlPrefix, new CredentialCache(), proxy)
		{
            var cache = _creds as CredentialCache;
            var uri = new Uri(urlPrefix);

            // Try the OAuth2 credential
            OAuth2Client.IStorage oauth2storage = null;
            if (storage != null)
            {
                oauth2storage = storage;
            }
            else
            {
                try
                {
                    var s = OAuth2Client.Storage.JsonFileStorage.Default as OAuth2Client.IStorage;
                    s.GetSecrets();
                    oauth2storage = s;
                }
                catch (System.IO.FileNotFoundException)
                {
                    // swallowed - meaning no oauth2 secrets configured.
                }
            }
            if (oauth2storage != null)
            {
                cache.Add(uri,
                    "Bearer",
                    new OAuth2Client.OAuth2Credential(
                        "apiv1",
                        oauth2storage,
                        proxy != null ? proxy.CreateWebProxy() : null
                        )
                    );
            }

			if(String.IsNullOrEmpty(username))
            {
                if (integratedAuth.GetValueOrDefault(true))
                { // no constructor args - so use default integrated identity unless they say no.
                    cache.Add(uri, "NTLM", CredentialCache.DefaultNetworkCredentials);
                    cache.Add(uri, "Negotiate", CredentialCache.DefaultNetworkCredentials);
                }
			}
            else
            {
                var userPassCred = new NetworkCredential(username, password);
                cache.Add(uri, "Basic", userPassCred);

                if (!integratedAuth.GetValueOrDefault(false))
                { // If there's a username, we'll assume the user doesn't want Windows Auth unless they ask.
                    cache.Add(uri, "NTLM", userPassCred);
                    cache.Add(uri, "Negotiate", userPassCred);
                }
            }
		}
    }
}