//  Copyright 2020 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Security.Audit
{
#pragma warning disable 1591
    /// <summary>
    /// Access rights for system audit policy.
    /// </summary>
    public enum AuditAccessRights : uint
    {
        [SDKName("AUDIT_SET_SYSTEM_POLICY")]
        SetSystemPolicy = 0x0001,
        [SDKName("AUDIT_QUERY_SYSTEM_POLICY")]
        QuerySystemPolicy = 0x0002,
        [SDKName("AUDIT_SET_USER_POLICY")]
        SetUserPolicy = 0x0004,
        [SDKName("AUDIT_QUERY_USER_POLICY")]
        QueryUserPolicy = 0x0008,
        [SDKName("AUDIT_ENUMERATE_USERS")]
        EnumerateUsers = 0x0010,
        [SDKName("AUDIT_SET_MISC_POLICY")]
        SetMiscPolicy = 0x0020,
        [SDKName("AUDIT_QUERY_MISC_POLICY")]
        QueryMiscPolicy = 0x0040,
        All = WriteOwner | WriteDac | ReadControl | Delete | SetSystemPolicy | QuerySystemPolicy |
            SetUserPolicy | QueryUserPolicy | EnumerateUsers | SetMiscPolicy | QueryMiscPolicy,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity,
    }
}
