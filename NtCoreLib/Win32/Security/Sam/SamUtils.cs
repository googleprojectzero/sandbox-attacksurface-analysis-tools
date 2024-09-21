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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Security.Sam
{
    internal static class SamUtils
    {
        public const string SAM_SERVER_NT_TYPE_NAME = "SamServer";
        public const string SAM_DOMAIN_NT_TYPE_NAME = "SamDomain";
        public const string SAM_USER_NT_TYPE_NAME = "SamUser";
        public const string SAM_GROUP_NT_TYPE_NAME = "SamGroup";
        public const string SAM_ALIAS_NT_TYPE_NAME = "SamAlias";

        public static GenericMapping GetSamServerGenericMapping()
        {
            return new GenericMapping()
            {
                GenericRead = SamServerAccessRights.ReadControl | SamServerAccessRights.EnumerateDomains,
                GenericWrite = SamServerAccessRights.ReadControl | SamServerAccessRights.Shutdown | SamServerAccessRights.Initialize | SamServerAccessRights.CreateDomain,
                GenericExecute = SamServerAccessRights.ReadControl | SamServerAccessRights.Connect | SamServerAccessRights.LookupDomain,
                GenericAll = SamServerAccessRights.ReadControl | SamServerAccessRights.WriteDac | SamServerAccessRights.WriteOwner | SamServerAccessRights.Delete |
                    SamServerAccessRights.EnumerateDomains | SamServerAccessRights.Shutdown | SamServerAccessRights.Initialize | SamServerAccessRights.CreateDomain |
                    SamServerAccessRights.Connect | SamServerAccessRights.LookupDomain
            };
        }

        public static GenericMapping GetSamDomainGenericMapping()
        {
            return new GenericMapping()
            {
                GenericRead = SamDomainAccessRights.ReadControl | SamDomainAccessRights.ReadOtherParameters | SamDomainAccessRights.GetAliasMembership,
                GenericWrite = SamDomainAccessRights.ReadControl | SamDomainAccessRights.WriteOtherParameters | SamDomainAccessRights.WritePasswordParams | SamDomainAccessRights.CreateAlias 
                | SamDomainAccessRights.CreateGroup | SamDomainAccessRights.CreateUser | SamDomainAccessRights.AdministerServer,
                GenericExecute = SamDomainAccessRights.ReadControl | SamDomainAccessRights.ReadPasswordParameters | SamDomainAccessRights.ListAccounts | SamDomainAccessRights.Lookup,
                GenericAll = SamDomainAccessRights.ReadControl | SamDomainAccessRights.WriteDac | SamDomainAccessRights.WriteOwner | SamDomainAccessRights.Delete |
                    SamDomainAccessRights.ReadOtherParameters | SamDomainAccessRights.GetAliasMembership | SamDomainAccessRights.WriteOtherParameters | SamDomainAccessRights.WritePasswordParams | SamDomainAccessRights.CreateAlias
                | SamDomainAccessRights.CreateGroup | SamDomainAccessRights.CreateUser | SamDomainAccessRights.AdministerServer | SamDomainAccessRights.ReadPasswordParameters | SamDomainAccessRights.ListAccounts | SamDomainAccessRights.Lookup
            };
        }

        public static GenericMapping GetSamUserGenericMapping()
        {
            return new GenericMapping()
            {
                GenericRead = SamUserAccessRights.ReadControl | SamUserAccessRights.ReadPreferences | SamUserAccessRights.ReadLogon | SamUserAccessRights.ReadAccount | 
                    SamUserAccessRights.ListGroups | SamUserAccessRights.ReadGroupInformation,
                GenericWrite = SamUserAccessRights.ReadControl | SamUserAccessRights.WritePreferences | SamUserAccessRights.ChangePassword,
                GenericExecute = SamUserAccessRights.ReadControl | SamUserAccessRights.ReadGeneral | SamUserAccessRights.ChangePassword,
                GenericAll = SamUserAccessRights.ReadControl | SamUserAccessRights.WriteDac | SamUserAccessRights.WriteOwner | SamUserAccessRights.Delete |
                SamUserAccessRights.ReadPreferences | SamUserAccessRights.ReadLogon | SamUserAccessRights.ReadAccount | SamUserAccessRights.ListGroups | SamUserAccessRights.ReadGroupInformation |
                SamUserAccessRights.WritePreferences | SamUserAccessRights.ChangePassword | SamUserAccessRights.ReadGeneral | SamUserAccessRights.ForcePasswordChange |
                SamUserAccessRights.WriteAccount | SamUserAccessRights.WriteGroupInformation
            };
        }

        public static GenericMapping GetSamGroupGenericMapping()
        {
            return new GenericMapping()
            {
                GenericRead = SamGroupAccessRights.ReadControl | SamGroupAccessRights.ListMembers,
                GenericWrite = SamGroupAccessRights.ReadControl | SamGroupAccessRights.WriteAccount | SamGroupAccessRights.AddMember | SamGroupAccessRights.RemoveMember,
                GenericExecute = SamGroupAccessRights.ReadControl | SamGroupAccessRights.ReadInformation,
                GenericAll = SamGroupAccessRights.ReadControl | SamGroupAccessRights.WriteDac | SamGroupAccessRights.WriteOwner | SamGroupAccessRights.Delete |
                    SamGroupAccessRights.ListMembers | SamGroupAccessRights.WriteAccount | SamGroupAccessRights.AddMember | SamGroupAccessRights.RemoveMember |
                    SamGroupAccessRights.ReadInformation
            };
        }

        public static GenericMapping GetSamAliasGenericMapping()
        {
            return new GenericMapping()
            {
                GenericRead = SamAliasAccessRights.ReadControl | SamAliasAccessRights.ListMembers,
                GenericWrite = SamAliasAccessRights.ReadControl | SamAliasAccessRights.WriteAccount | SamAliasAccessRights.AddMember | SamAliasAccessRights.RemoveMember,
                GenericExecute = SamAliasAccessRights.ReadControl | SamAliasAccessRights.ReadInformation,
                GenericAll = SamAliasAccessRights.ReadControl | SamAliasAccessRights.WriteDac | SamAliasAccessRights.WriteOwner | SamAliasAccessRights.Delete |
                    SamAliasAccessRights.ListMembers | SamAliasAccessRights.WriteAccount | SamAliasAccessRights.AddMember | SamAliasAccessRights.RemoveMember |
                    SamAliasAccessRights.ReadInformation
            };
        }

        public static NtResult<IReadOnlyList<T>> SamEnumerateObjects<T, S>(SafeSamHandle handle,
                SecurityEnumDelegate<SafeSamHandle, SafeSamMemoryBuffer> func, Func<S, T> select_object,
                bool throw_on_error) where S : struct
        {
            return SecurityNativeMethods.EnumerateObjects(handle, func, select_object, throw_on_error);
        }
    }
}
