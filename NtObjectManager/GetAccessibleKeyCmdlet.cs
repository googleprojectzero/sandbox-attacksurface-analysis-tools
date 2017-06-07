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
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Get a list of Registry Keys that can be opened by a specificed token.</para>
    /// <para type="description">This cmdlet checks a registry key and optionally tries to determine
    /// if one or more specified tokens can open them to them. If no tokens are specified the current process
    /// token is used.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-AccessibleKey \Registry\Machine\Software</code>
    ///   <para>Check accessible keys \Registry\Machine\Software for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleKey \Registry\Machine\Software -ProcessIds 1234,5678</code>
    ///   <para>Check accessible keys \Registry\Machine\Software for the process tokens of PIDs 1234 and 5678</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleKey \Registry\Machine\Software -Recurse</code>
    ///   <para>Check recursively for accessible keys \Registry\Machine\Software for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleKey HKLM\Software -Win32Path -Recurse</code>
    ///   <para>Check recursively for accessible keys NT path HKEY_LOCAL_MACHINE for the current process token using a Win32 path.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleKey HKCU -Recurse -Tokens $token -AccessRights GenericWrite</code>
    ///   <para>Get all keys with can be written to in HKEY_CURRENT_USER by a low integrity copy of current token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleKey")]
    public class GetAccessibleKeyCmdlet : CommonAccessBaseCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the key path to check. Must be a native (such as \Registry\Machine\Blah) unless -Win32Path is set.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public string Path { get; set; }

        /// <summary>
        /// <para type="description">Specify the key path is in a Win32 format, such as HKLM\Blah.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Win32Path { get; set; }

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

        private static NtKey OpenKey(string name, bool win32_path, bool open_link, bool open_for_backup)
        {
            if (win32_path)
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
                return NtKey.Open(obja, KeyAccessRights.MaximumAllowed, 0);
            }
        }

        private void CheckAccess(TokenEntry token, NtKey key, AccessMask access_rights, SecurityDescriptor sd)
        {
            NtType type = key.NtType;
            AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, type.GenericMapping);
            if (!granted_access.IsEmpty && granted_access.IsAllAccessGranted(access_rights))
            {
                WriteAccessCheckResult(Win32Path ? key.Win32Path : key.FullPath, type.Name, granted_access, type.GenericMapping, 
                    sd.ToSddl(), typeof(KeyAccessRights), token.Information);
            }
        }

        private void CheckAccessUnderImpersonation(TokenEntry token, NtKey key)
        {
            NtKey new_key = null;
            try
            {
                using (ObjectAttributes obj_attributes = new ObjectAttributes(string.Empty,
                    AttributeFlags.CaseInsensitive | AttributeFlags.OpenLink, key))
                {

                    bool success;

                    using (token.Token.Impersonate())
                    {
                        success = NtKey.Open(obj_attributes, KeyAccessRights.MaximumAllowed, 0, out new_key).IsSuccess();
                    }

                    if (success)
                    {
                        WriteAccessCheckResult(key.FullPath, key.NtType.Name, new_key.GrantedAccessMask, key.NtType.GenericMapping,
                            String.Empty, typeof(KeyAccessRights), token.Information);
                    }
                }
            }
            finally
            {
                new_key?.Dispose();
            }
        }

        private void DumpKey(IEnumerable<TokenEntry> tokens, AccessMask access_rights, bool open_for_backup, NtKey key)
        {
            if (Stopping)
            {
                return;
            }

            if (key.IsAccessGranted(KeyAccessRights.ReadControl))
            {
                SecurityDescriptor sd = key.SecurityDescriptor;
                foreach (var token in tokens)
                {
                    CheckAccess(token, key, access_rights, sd);
                }
            }
            else
            {
                // If we can't read security descriptor then try opening the key.
                foreach (var token in tokens)
                {
                    CheckAccessUnderImpersonation(token, key);
                }
            }

            if (Recurse && key.IsAccessGranted(KeyAccessRights.EnumerateSubKeys))
            {
                using (var keys = key.QueryAccessibleKeys(KeyAccessRights.MaximumAllowed, true, open_for_backup).ToDisposableList())
                {
                    foreach (NtKey subkey in keys)
                    {
                        DumpKey(tokens, access_rights, open_for_backup, subkey);
                    }
                }
            }
        }

        internal override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            bool open_for_backup = false;
            using (NtToken process_token = NtToken.OpenProcessToken())
            {
                open_for_backup = process_token.SetPrivilege(TokenPrivilegeValue.SeBackupPrivilege, PrivilegeAttributes.Enabled);
                if (!open_for_backup)
                {
                    WriteWarning("Current process doesn't have SeBackupPrivilege, results may be inaccurate");
                }
            }

            using (NtKey key = OpenKey(Path, Win32Path, false, open_for_backup))
            {
                DumpKey(tokens, key.NtType.MapGenericRights(AccessRights), open_for_backup, key);
            }
        }
    }
}
