//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtCoreLib.Utilities.Memory;

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// Class to represent an IKE name credential.
/// </summary>
public sealed class IkeNameCredential : IkeCredential
{
    /// <summary>
    /// The credential principal name.
    /// </summary>
    public string PrincipalName { get; }

    internal IkeNameCredential(IKEEXT_CREDENTIAL1 creds) : base(creds)
    {
        var cred = creds.cred.ReadStruct<IKEEXT_NAME_CREDENTIAL0>();
        PrincipalName = cred.principalName;
    }

    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The pair as a string.</returns>
    public override string ToString()
    {
        return $"{AuthenticationMethodType} - {PrincipalName}";
    }
}
