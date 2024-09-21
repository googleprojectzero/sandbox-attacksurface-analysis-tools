//  Copyright 2022 Google LLC. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using NtCoreLib.Win32.Security.Authentication.Kerberos.Builder;
using System;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos.Client;

/// <summary>
/// Class to represent an AS request with a known encryption key.
/// </summary>
public sealed class KerberosASRequest : KerberosASRequestBase
{
    #region Public Properties
    /// <summary>
    /// The key for the principal.
    /// </summary>
    public KerberosAuthenticationKey Key { get; }

    /// <summary>
    /// Disable sending initial pre-authentication.
    /// </summary>
    public bool DisablePreAuthentication { get; set; }
    #endregion

    #region Constructors
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="key">The kerberos key for the user.</param>
    public KerberosASRequest(KerberosAuthenticationKey key) 
        : this(key, key?.Name, key?.Realm)
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="key">The kerberos key for the user.</param>
    /// <param name="client_name">The client name for the ticket.</param>
    /// <param name="realm">The client and server realm realm.</param>
    public KerberosASRequest(KerberosAuthenticationKey key, KerberosPrincipalName client_name, string realm)
    {
        Key = key ?? throw new ArgumentNullException(nameof(key));
        ClientName = client_name ?? throw new ArgumentNullException(nameof(client_name));
        Realm = realm ?? throw new ArgumentNullException(nameof(realm));
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Convert the request to a builder.
    /// </summary>
    /// <returns>The builder.</returns>
    public override KerberosKDCRequestBuilder ToBuilder()
    {
        var ret = base.ToBuilder();
        if (!DisablePreAuthentication)
        {
            ret.AddPreAuthenticationData(KerberosPreAuthenticationDataEncTimestamp.Create(KerberosTime.Now, Key));
        }
        return ret;
    }
    #endregion
}
