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

using System;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos.Builder;

/// <summary>
/// Class to represent the KERB_AD_RESTRICTION_ENTRY AD type builder.
/// </summary>
public sealed class KerberosAuthorizationDataRestrictionEntryBuilder : KerberosAuthorizationDataBuilder
{
    /// <summary>
    /// Flags.
    /// </summary>
    public KerberosRestrictionEntryFlags Flags { get; set; }
    /// <summary>
    /// Token IL.
    /// </summary>
    public TokenIntegrityLevel IntegrityLevel { get; set; }
    /// <summary>
    /// Machine ID.
    /// </summary>
    public byte[] MachineId { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public KerberosAuthorizationDataRestrictionEntryBuilder() 
        : base(KerberosAuthorizationDataType.KERB_AD_RESTRICTION_ENTRY)
    {
        IntegrityLevel = TokenIntegrityLevel.High;
        MachineId = new byte[32];
        new Random().NextBytes(MachineId);
    }

    /// <summary>
    /// Create the Kerberos authorization data.
    /// </summary>
    /// <returns>The kerberos authorization data.</returns>
    public override KerberosAuthorizationData Create()
    {
        return new KerberosAuthorizationDataRestrictionEntry(Flags, 
            IntegrityLevel, MachineId);
    }
}
