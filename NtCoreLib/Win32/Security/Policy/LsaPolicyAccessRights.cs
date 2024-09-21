//  Copyright 2021 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Access rights for the LSA policy.
    /// </summary>
    [Flags]
    public enum LsaPolicyAccessRights : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("POLICY_VIEW_LOCAL_INFORMATION")]
        ViewLocalInformation = 0x00000001,
        [SDKName("POLICY_VIEW_AUDIT_INFORMATION")]
        ViewAuditInformation = 0x00000002,
        [SDKName("POLICY_GET_PRIVATE_INFORMATION")]
        GetPrivateInformation = 0x00000004,
        [SDKName("POLICY_TRUST_ADMIN")]
        TrustAdmin = 0x00000008,
        [SDKName("POLICY_CREATE_ACCOUNT")]
        CreateAccount = 0x00000010,
        [SDKName("POLICY_CREATE_SECRET")]
        CreateSecret = 0x00000020,
        [SDKName("POLICY_CREATE_PRIVILEGE")]
        CreatePrivilege = 0x00000040,
        [SDKName("POLICY_SET_DEFAULT_QUOTA_LIMITS")]
        SetDefaultQuotaLimits = 0x00000080,
        [SDKName("POLICY_SET_AUDIT_REQUIREMENTS")]
        SetAuditRequirements = 0x00000100,
        [SDKName("POLICY_AUDIT_LOG_ADMIN")]
        AuditLogAdmin = 0x00000200,
        [SDKName("POLICY_SERVER_ADMIN")]
        ServerAdmin = 0x00000400,
        [SDKName("POLICY_LOOKUP_NAMES")]
        LookupNames = 0x00000800,
        [SDKName("POLICY_NOTIFICATION")]
        Notification = 0x00001000,
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
