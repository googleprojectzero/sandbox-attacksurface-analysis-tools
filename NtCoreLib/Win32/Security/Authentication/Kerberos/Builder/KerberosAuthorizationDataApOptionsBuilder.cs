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

namespace NtCoreLib.Win32.Security.Authentication.Kerberos.Builder;

/// <summary>
/// Class to represent the AD-AUTH-DATA-AP-OPTIONS authorization data builder.
/// </summary>
public sealed class KerberosAuthorizationDataApOptionsBuilder : KerberosAuthorizationDataBuilder
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public KerberosAuthorizationDataApOptionsBuilder() 
        : base(KerberosAuthorizationDataType.AD_AUTH_DATA_AP_OPTIONS)
    {
    }

    /// <summary>
    /// Flags for the AD-AUTH-DATA-AP-OPTIONS authorization data.
    /// </summary>
    public KerberosApOptionsFlags Flags { get; set; }

    /// <summary>
    /// Create the Kerberos authorization data.
    /// </summary>
    /// <returns>The kerberos authorization data.</returns>
    public override KerberosAuthorizationData Create()
    {
        return new KerberosAuthorizationDataApOptions(Flags);
    }
}
