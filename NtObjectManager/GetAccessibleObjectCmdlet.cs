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
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Get a list of NT objects that can be opened by a specificed token.</para>
    /// <para type="description">This cmdlet checks a NT object key and optionally tries to determine
    /// if one or more specified tokens can open them. If no tokens are specified the current process
    /// token is used.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-AccessibleObject \BaseNamedObjects</code>
    ///   <para>Check accessible objects under \ for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleObject \BaseNamedObjects -ProcessIds 1234,5678</code>
    ///   <para>Check accessible objects under \BaseNamedObjects for the process tokens of PIDs 1234 and 5678</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleObject \BaseNamedObjects -Recurse</code>
    ///   <para>Check recursively for accessible objects under \BaseNamedObjects for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleObject \BaseNamedObjects -Recurse -MaxDepth 5</code>
    ///   <para>Check recursively for accessible objects under \BaseNamedObjects for the current process token to a maximum depth of 5.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleObject -Win32Path \ -Recurse</code>
    ///   <para>Check recursively for accessible objects under the user's based named objects for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleObject \BaseNamedObjects -Recurse -Tokens $token -AccessRights GenericWrite</code>
    ///   <para>Get all object which can be written to in \BaseNamedObjects by a low integrity copy of current token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleObject")]
    public class GetAccessibleObjectCmdlet : GetAccessiblePathCmdlet
    {
        private static string _base_named_objects = NtDirectory.GetBasedNamedObjects();

        /// <summary>
        /// <para type="description">Generic access rights to check for in an object's access.</para>
        /// </summary>
        [Parameter]
        public GenericAccessRights AccessRights { get; private set; }

        /// <summary>
        /// <para type="description">If AccessRights specified require that the all must be present to
        /// be considered a match.</para>
        /// </summary>
        [Parameter]
        public bool RequireAllAccess { get; private set; }

        /// <summary>
        /// <para type="description">Specify list of NT object types to filter on.</para>
        /// </summary>
        [Parameter]
        public string[] TypeFilter { get; set; }

        /// <summary>
        /// <para type="description">Specify to find objects based on handles rather than enumerating named paths.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "handles")]
        public SwitchParameter FromHandles { get; set; }

        /// <summary>
        /// <para type="description">Specify when enumerating handles to also check unnamed objects.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "handles")]
        public SwitchParameter CheckUnnamed { get; set; }

        private string ConvertPath(NtObject obj)
        {
            string path = obj.FullPath;
            if (FormatWin32Path)
            {
                if (path.Equals(_base_named_objects, StringComparison.OrdinalIgnoreCase))
                {
                    return @"\";
                }
                else if (path.StartsWith(_base_named_objects, StringComparison.OrdinalIgnoreCase))
                {
                    return path.Substring(_base_named_objects.Length);
                }
            }
            return path;
        }

        private bool IsAccessGranted(AccessMask granted_access, AccessMask access_rights)
        {
            if (granted_access.IsEmpty)
            {
                return false;
            }

            if (access_rights.IsEmpty)
            {
                return true;
            }

            if (RequireAllAccess && granted_access.IsAllAccessGranted(access_rights))
            {
                return true;
            }

            return granted_access.IsAccessGranted(access_rights);
        }

        private void CheckAccess(TokenEntry token, NtObject obj, NtType type, AccessMask access_rights, SecurityDescriptor sd)
        {
            AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, type.GenericMapping);
            if (IsAccessGranted(granted_access, access_rights))
            {
                WriteAccessCheckResult(ConvertPath(obj), type.Name, granted_access, type.GenericMapping,
                    sd.ToSddl(), type.AccessRightsType, token.Information);
            }
        }

        private void CheckAccessUnderImpersonation(TokenEntry token, NtType type, AccessMask access_rights, NtObject obj)
        {
            using (ObjectAttributes obj_attributes = new ObjectAttributes(string.Empty,
                AttributeFlags.CaseInsensitive, obj))
            {
                using (var result = token.Token.RunUnderImpersonate(() => type.Open(obj_attributes, GenericAccessRights.MaximumAllowed, false)))
                {
                    if (result.IsSuccess && IsAccessGranted(result.Result.GrantedAccessMask, access_rights))
                    {
                        WriteAccessCheckResult(ConvertPath(obj), type.Name, result.Result.GrantedAccessMask, type.GenericMapping,
                            String.Empty, type.AccessRightsType, token.Information);
                    }
                }
            }
        }

        private static bool IsTypeFiltered(string type_name, HashSet<string> type_filter)
        {
            if (type_filter.Count > 0)
            {
                return type_filter.Contains(type_name);
            }
            return true;
        }

        private void DumpObject(IEnumerable<TokenEntry> tokens, HashSet<string> type_filter, AccessMask access_rights, NtObject obj)
        {
            NtType type = obj.NtType;
            if (!IsTypeFiltered(type.Name, type_filter))
            {
                return;
            }

            AccessMask desired_access = type.MapGenericRights(access_rights);
            var result = obj.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
            if (result.IsSuccess)
            {
                foreach (var token in tokens)
                {
                    CheckAccess(token, obj, type, desired_access, result.Result);
                }
            }
            else
            {
                // If we can't read security descriptor then try opening the object.
                foreach (var token in tokens)
                {
                    CheckAccessUnderImpersonation(token, type, desired_access, obj);
                }
            }
        }

        private void DumpDirectory(IEnumerable<TokenEntry> tokens, HashSet<string> type_filter, 
            AccessMask access_rights, NtDirectory dir, int current_depth)
        {
            DumpObject(tokens, type_filter, access_rights, dir);

            if (Stopping || current_depth <= 0)
            {
                return;
            }

            if (Recurse && dir.IsAccessGranted(DirectoryAccessRights.Query))
            {
                foreach (var entry in dir.Query())
                {
                    if (entry.IsDirectory)
                    {
                        using (var new_dir = OpenDirectory(entry.Name, dir))
                        {
                            if (new_dir.IsSuccess)
                            {
                                DumpDirectory(tokens, type_filter, access_rights, new_dir.Result, current_depth - 1);
                            }
                            else
                            {
                                WriteAccessWarning(dir, entry.Name, new_dir.Status);
                            }
                        }
                    }
                    else
                    {
                        NtType type = entry.NtType;
                        if (IsTypeFiltered(type.Name, type_filter))
                        {
                            if (type.CanOpen)
                            {
                                using (var result = OpenObject(entry, dir, GenericAccessRights.MaximumAllowed))
                                {
                                    if (result.IsSuccess)
                                    {
                                        DumpObject(tokens, type_filter, access_rights, result.Result);
                                    }
                                    else
                                    {
                                        WriteAccessWarning(dir, entry.Name, result.Status);
                                    }
                                }
                            }
                            else
                            {
                                WriteWarning(String.Format(@"Can't open {0}\{1} with type {2}", dir.FullPath, entry.Name, entry.NtTypeName));
                            }
                        }
                    }
                }
            }
        }

        private NtResult<NtObject> OpenObject(ObjectDirectoryInformation entry, NtObject root, AccessMask desired_access)
        {
            NtType type = entry.NtType;
            using (var obja = new ObjectAttributes(entry.Name, AttributeFlags.CaseInsensitive, root))
            {
                return type.Open(obja, desired_access, false);
            }
        }

        private NtResult<NtDirectory> OpenDirectory(string path, NtObject root)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path,
                AttributeFlags.CaseInsensitive, root))
            {
                var result = NtDirectory.Open(obja, DirectoryAccessRights.Query | DirectoryAccessRights.ReadControl, false);
                if (result.IsSuccess || result.Status != NtStatus.STATUS_ACCESS_DENIED)
                {
                    return result;
                }

                // Try again with just Query, if we can't even do this we give up.
                return NtDirectory.Open(obja, DirectoryAccessRights.Query, false);
            }
        }

        private void RunAccessCheckPath(IEnumerable<TokenEntry> tokens, HashSet<string> type_filter)
        {
            string base_path = Path;
            if (base_path == null)
            {
                base_path = Win32Path.TrimStart('\\');
                if (String.IsNullOrEmpty(base_path))
                {
                    base_path = _base_named_objects;
                }
                else
                {
                    base_path = String.Format(@"{0}\{1}", _base_named_objects, base_path);
                }
            }
            if (!base_path.StartsWith(@"\"))
            {
                WriteWarning("Path doesn't start with \\. Perhaps you want to specify -Win32Path instead?");
            }

            using (var result = OpenDirectory(base_path, null))
            {
                if (result.IsSuccess)
                {
                    DumpDirectory(tokens, type_filter, AccessRights, result.Result, GetMaxDepth());
                }
            }
        }

        private void RunAccessCheckHandles(IEnumerable<TokenEntry> tokens, HashSet<string> type_filter)
        {
            //using (NtToken process_token = NtToken.OpenProcessToken())
            //{
            //    if (!process_token.SetPrivilege(TokenPrivilegeValue.SeDebugPrivilege, PrivilegeAttributes.Enabled))
            //    {
            //        WriteWarning("Current process doesn't have SeDebugPrivilege, results may be inaccurate");
            //    }
            //}

            //if (type_filter.Count == 0)
            //{
            //    WriteWarning("Checking handle access without any type filtering can hang. Perhaps specifying the types using -TypeFilter.");
            //}

            //var handles = NtSystemInfo.GetHandles(-1, false).Where(h => IsTypeFiltered(h.ObjectType, type_filter)).GroupBy(h => h.ProcessId);
            //HashSet<ulong> checked_objects = new HashSet<ulong>();

            //try
            //{
            //    foreach (var group in handles)
            //    {
            //        using (var proc = NtProcess.Open(group.Key, ProcessAccessRights.DupHandle, false))
            //        {
            //        }


            //            try
            //            {

            //                using (NtAlpc obj = NtAlpc.DuplicateFrom(proc, new IntPtr(handle.Handle)))
            //                {
            //                    string name = obj.FullPath;
            //                    // We only care about named ALPC ports.
            //                    if (String.IsNullOrEmpty(name))
            //                    {
            //                        continue;
            //                    }

            //                    if (!ports.Add(name))
            //                    {
            //                        continue;
            //                    }

            //                    SecurityDescriptor sd = obj.SecurityDescriptor;
            //                    string sddl = sd.ToSddl();
            //                    foreach (TokenEntry token in tokens)
            //                    {
            //                        AccessMask granted_access = NtSecurity.GetAllowedAccess(sd, token.Token,
            //                            AlpcAccessRights.Connect, alpc_type.GenericMapping);
            //                        if (granted_access.IsEmpty)
            //                        {
            //                            continue;
            //                        }
            //                        AccessMask maximum_access = NtSecurity.GetMaximumAccess(sd,
            //                            token.Token, alpc_type.GenericMapping);
            //                        WriteAccessCheckResult(name, alpc_type.Name, maximum_access,
            //                            alpc_type.GenericMapping, sddl, typeof(AlpcAccessRights), token.Information);
            //                    }
            //                }
            //            }
            //            catch (NtException)
            //            {
            //            }
            //    }
            //}
            //finally
            //{
            //    foreach (NtProcess proc in pid_to_process.Values)
            //    {
            //        proc?.Close();
            //    }
            //}
        }

        internal override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            HashSet<string> type_filter = new HashSet<string>(TypeFilter ?? new string[0], StringComparer.OrdinalIgnoreCase);

            if (FromHandles)
            {
                RunAccessCheckHandles(tokens, type_filter);
            }
            else
            {
                RunAccessCheckPath(tokens, type_filter);
            }
        }
    }
}
