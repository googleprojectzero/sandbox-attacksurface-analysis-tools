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

using NtCoreLib.Utilities.ASN1.Builder;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Win32.Security.Authentication.CredSSP;

/// <summary>
/// Class to represent a TSRemoteGuardCreds structure.
/// </summary>
public sealed class TSRemoteGuardCredentials : TSCredentials
{
    /// <summary>
    /// The remote guard logon credentials.
    /// </summary>
    public TSRemoteGuardPackageCredentials LogonCred { get; }

    /// <summary>
    /// The remote guard supplemental credentials.
    /// </summary>
    public IEnumerable<TSRemoteGuardPackageCredentials> SupplementalCreds { get; }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="logon_cred">The logon credentials.</param>
    /// <param name="supplemental_creds">Optional supplemental credentials.</param>
    public TSRemoteGuardCredentials(TSRemoteGuardPackageCredentials logon_cred,
        IEnumerable<TSRemoteGuardPackageCredentials> supplemental_creds = null) : base(TSCredentialsType.RemoteGuard)
    {
        LogonCred = logon_cred;
        SupplementalCreds = supplemental_creds?.ToList().AsReadOnly();
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="cred_buffer">Credentials buffer for the logon creds.</param>
    /// <param name="package_name">Package name for the logon creds.</param>
    /// <param name="supplemental_creds">Optional supplemental credentials.</param>
    public TSRemoteGuardCredentials(string package_name, byte[] cred_buffer, 
        IEnumerable<TSRemoteGuardPackageCredentials> supplemental_creds = null) 
        : this(new TSRemoteGuardPackageCredentials(package_name, cred_buffer), supplemental_creds)
    {
    }

    private protected override byte[] GetCredentials()
    {
        DERBuilder builder = new();
        using (var seq = builder.CreateSequence())
        {
            seq.WriteContextSpecific(0, LogonCred);
            seq.WriteContextSpecific(1, SupplementalCreds);
        }
        return builder.ToArray();
    }
}
