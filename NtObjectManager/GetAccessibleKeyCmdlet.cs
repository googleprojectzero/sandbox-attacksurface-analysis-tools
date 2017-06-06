//  Copyright 2017 Google Inc. All Rights Reserved.
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

using NtApiDotNet;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Get a list of Registry Keys that can be opened by a specificed process..</para>
    /// <para type="description">This cmdlet checks a registry key and optionally ittries to determine
    /// if one or more specified processes can open them to them. If no processes are specified using the
    /// -ProcessIds parameter then the current process token is used.</para>
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AccessibleKey")]
    public class GetAccessibleKeyCmdlet : CommonAccessBaseCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the key path to check. Can be in win32 form (such as HKLM\Blah) or native (such as \Registry\Machine\Blah)</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public string Path { get; set; }

        /// <summary>
        /// <para type="description">Specify a set of access rights which the key must at least be accessible for to count as an access.</para>
        /// </summary>
        [Parameter]
        public KeyAccessRights AccessRights { get; set; }

        /// <summary>
        /// <para type="description">Specify whether to recursively check the key for subkeys to access.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Recurse { get; set; }

        private static NtKey OpenKey(string name, bool open_link)
        {
            if (!name.StartsWith(@"\"))
            {
                name = NtKeyUtils.Win32KeyNameToNt(name);
            }

            AttributeFlags flags = AttributeFlags.CaseInsensitive;
            if (open_link)
            {
                flags |= AttributeFlags.OpenLink;
            }

            using (ObjectAttributes obja = new ObjectAttributes(name,
                flags, null))
            {
                return NtKey.Open(obja, KeyAccessRights.MaximumAllowed);
            }
        }

        private void CheckAccess(ProcessInformation proc_info, NtKey key, AccessMask access_rights, SecurityDescriptor sd)
        {
            NtType type = key.NtType;
            if (!key.IsAccessGranted(KeyAccessRights.ReadControl))
            {
                return;
            }

            AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, proc_info.Token, type.GenericMapping);
            if (!granted_access.IsEmpty && granted_access.IsAllAccessGranted(access_rights))
            {
                WriteAccessCheckResult(key.FullPath, type.Name, granted_access, type.GenericMapping, sd.ToSddl(), typeof(KeyAccessRights), proc_info);
            }
        }

        private void DumpKey(IList<ProcessInformation> processes, AccessMask access_rights, NtKey key)
        {
            if (Stopping)
            {
                return;
            }

            if (key.IsAccessGranted(KeyAccessRights.ReadControl))
            {
                SecurityDescriptor sd = key.SecurityDescriptor;
                foreach (var proc_info in processes)
                {
                    CheckAccess(proc_info, key, access_rights, sd);
                }
            }

            if (Recurse && key.IsAccessGranted(KeyAccessRights.EnumerateSubKeys))
            {
                using (var keys = key.QueryAccessibleKeys(KeyAccessRights.MaximumAllowed, true).ToDisposableList())
                {
                    foreach (NtKey subkey in keys)
                    {
                        DumpKey(processes, access_rights, subkey);
                    }
                }
            }
        }

        internal override void RunAccessCheck(IList<ProcessInformation> processes)
        {
            using (NtKey key = OpenKey(Path, false))
            {
                DumpKey(processes, key.NtType.MapGenericRights(AccessRights), key);
            }
        }
    }
}
