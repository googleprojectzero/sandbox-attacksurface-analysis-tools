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

using NtApiDotNet.Utilities.Reflection;
using System;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Access rights for a firewall object.
    /// </summary>
    [Flags]
    public enum FirewallAccessRights : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("FWPM_ACTRL_ADD")]
        Add = 0x00000001,
        [SDKName("FWPM_ACTRL_ADD_LINK")]
        AddLink = 0x00000002,
        [SDKName("FWPM_ACTRL_BEGIN_READ_TXN")]
        BeginReadTxn = 0x00000004,
        [SDKName("FWPM_ACTRL_BEGIN_WRITE_TXN")]
        BeginWriteTxn = 0x00000008,
        [SDKName("FWPM_ACTRL_CLASSIFY")]
        Classify = 0x00000010,
        [SDKName("FWPM_ACTRL_ENUM")]
        Enum = 0x00000020,
        [SDKName("FWPM_ACTRL_OPEN")]
        Open = 0x00000040,
        [SDKName("FWPM_ACTRL_READ")]
        Read = 0x00000080,
        [SDKName("FWPM_ACTRL_READ_STATS")]
        ReadStats = 0x00000100,
        [SDKName("FWPM_ACTRL_SUBSCRIBE")]
        Subscribe = 0x00000200,
        [SDKName("FWPM_ACTRL_WRITE")]
        Write = 0x00000400,
        [SDKName("GENERIC_READ")]
        GenericRead = GenericAccessRights.GenericRead,
        [SDKName("GENERIC_WRITE")]
        GenericWrite = GenericAccessRights.GenericWrite,
        [SDKName("GENERIC_EXECUTE")]
        GenericExecute = GenericAccessRights.GenericExecute,
        [SDKName("GENERIC_ALL")]
        GenericAll = GenericAccessRights.GenericAll,
        [SDKName("DELETE")]
        Delete = GenericAccessRights.Delete,
        [SDKName("READ_CONTROL")]
        ReadControl = GenericAccessRights.ReadControl,
        [SDKName("WRITE_DAC")]
        WriteDac = GenericAccessRights.WriteDac,
        [SDKName("WRITE_OWNER")]
        WriteOwner = GenericAccessRights.WriteOwner,
        [SDKName("MAXIMUM_ALLOWED")]
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        [SDKName("ACCESS_SYSTEM_SECURITY")]
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
