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

using NtCoreLib;
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.Token;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="synopsis">Get a list of NT objects that can be opened by a specified token.</para>
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
///   <code>Get-AccessibleObject \ -Recurse -AccessRights GenericWrite</code>
///   <para>Check recursively for accessible objects under with write access.</para>
/// </example>
/// <example>
///   <code>Get-AccessibleObject \ -Recurse -AccessRights GenericWrite -AllowPartialAccess</code>
///   <para>Check recursively for accessible objects under with partial write access.</para>
/// </example>
/// <example>
///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleObject \BaseNamedObjects -Recurse -Tokens $token -AccessRights GenericWrite</code>
///   <para>Get all object which can be written to in \BaseNamedObjects by a low integrity copy of current token.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "AccessibleObject")]
[OutputType(typeof(CommonAccessCheckResult))]
public class GetAccessibleObjectCmdlet : GetAccessiblePathCmdlet<GenericAccessRights>
{
    private static readonly string _base_named_objects = NtDirectory.GetBasedNamedObjects();

    /// <summary>
    /// <para type="description">Specify list of NT object types to filter on.</para>
    /// </summary>
    [Parameter]
    public string[] TypeFilter { get; set; }

    /// <summary>
    /// <para type="description">Specify to find objects based on handles rather than enumerating named paths.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "handles")]
    [Alias("FromHandles")]
    public SwitchParameter FromHandle { get; set; }

    /// <summary>
    /// <para type="description">Specify when enumerating handles to also check unnamed objects.</para>
    /// </summary>
    [Parameter(ParameterSetName = "handles")]
    public SwitchParameter CheckUnnamed { get; set; }

    /// <summary>
    /// <para type="description">Specify to query all file device paths. Doing this might cause the cmdlet to hang.</para>
    /// </summary>
    [Parameter(ParameterSetName = "handles")]
    public SwitchParameter QueryAllDevicePaths { get; set; }

    private string GetObjectName(NtObject obj)
    {
        try
        {
            if (FromHandle && !QueryAllDevicePaths)
            {
                if (obj is NtGeneric generic && obj.NtTypeName == "File")
                {
                    using var typed = generic.ToTypedObject();
                    return GetObjectName(typed);
                }

                if (obj is NtFile file_obj && file_obj.DeviceType != FileDeviceType.DISK)
                {
                    return string.Empty;
                }
            }

            return obj.FullPath;
        }
        catch (NtException)
        {
            return string.Empty;
        }
    }

    private string ConvertPath(NtObject obj)
    {
        try
        {
            string path = GetObjectName(obj);
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
        catch
        {
            return string.Empty;
        }
    }

    private void CheckAccess(TokenEntry token, NtObject obj, NtType type, bool is_directory, 
        AccessMask access_rights, SecurityDescriptor sd)
    {
        AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, type.GenericMapping);
        if (IsAccessGranted(granted_access, access_rights))
        {
            WriteAccessCheckResult(ConvertPath(obj), type.Name, granted_access, type.GenericMapping,
                sd, type.AccessRightsType, is_directory, token.Information);
        }
    }

    private NtResult<NtObject> ReopenUnderImpersonation(TokenEntry token, NtType type, NtObject obj)
    {
        using ObjectAttributes obj_attributes = new(string.Empty,
           GetAttributeFlags(), obj);
        return token.Token.RunUnderImpersonate(() => type.Open(obj_attributes, GenericAccessRights.MaximumAllowed, false));
    }

    private void CheckAccessUnderImpersonation(TokenEntry token, NtType type, bool is_directory, 
        AccessMask access_rights, NtObject obj)
    {
        using var result = ReopenUnderImpersonation(token, type, obj);
        if (result.IsSuccess && IsAccessGranted(result.Result.GrantedAccessMask, access_rights))
        {
            WriteAccessCheckResult(ConvertPath(obj), type.Name, result.Result.GrantedAccessMask, type.GenericMapping,
                null, type.AccessRightsType, is_directory, token.Information);
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

    private void DumpObject(IEnumerable<TokenEntry> tokens, HashSet<string> type_filter, AccessMask access_rights, NtObject obj, bool is_directory)
    {
        NtType type = obj.NtType;
        if (!IsTypeFiltered(type.Name, type_filter))
        {
            return;
        }

        if (!IncludePath(obj.Name))
        {
            return;
        }

        AccessMask desired_access = type.MapGenericRights(access_rights);
        var result = GetSecurityDescriptor(obj);
        if (!result.IsSuccess && !obj.IsAccessMaskGranted(GenericAccessRights.ReadControl))
        {
            // Try and duplicate handle to see if we can just ask for ReadControl.
            using var dup_obj = obj.DuplicateObject(GenericAccessRights.ReadControl, AttributeFlags.None, DuplicateObjectOptions.None, false);
            if (dup_obj.IsSuccess)
            {
                result = GetSecurityDescriptor(dup_obj.Result);
            }
        }

        if (result.IsSuccess)
        {
            foreach (var token in tokens)
            {
                CheckAccess(token, obj, type, is_directory, desired_access, result.Result);
            }
        }
        else if (type.CanOpen)
        {
            // If we can't read security descriptor then try opening the object.
            foreach (var token in tokens)
            {
                CheckAccessUnderImpersonation(token, type, is_directory, desired_access, obj);
            }
        }

        // TODO: Do we need a warning here?
    }

    private void DumpDirectory(IEnumerable<TokenEntry> tokens, HashSet<string> type_filter, 
        AccessMask access_rights, NtDirectory dir, int current_depth)
    {
        DumpObject(tokens, type_filter, access_rights, dir, true);

        if (Stopping || current_depth <= 0)
        {
            return;
        }

        if (Recurse && dir.IsAccessGranted(DirectoryAccessRights.Query))
        {
            foreach (var entry in dir.Query())
            {
                if (FilterPath(entry.Name))
                {
                    continue;
                }

                if (entry.IsDirectory || (FollowLink && entry.IsSymbolicLink))
                {
                    using var new_dir = OpenDirectory(entry.Name, dir);
                    if (new_dir.IsSuccess)
                    {
                        if (FollowPath(new_dir.Result.FullPath))
                        {
                            DumpDirectory(tokens, type_filter, access_rights, new_dir.Result, current_depth - 1);
                        }
                    }
                    else
                    {
                        if (entry.IsDirectory || new_dir.Status != NtStatus.STATUS_OBJECT_TYPE_MISMATCH)
                        {
                            WriteAccessWarning(dir, entry.Name, new_dir.Status);
                        }
                    }
                }
                else
                {
                    NtType type = entry.NtType;
                    if (IsTypeFiltered(type.Name, type_filter) && !type.Name.Equals("Device", StringComparison.OrdinalIgnoreCase) 
                                                               && !type.Name.Equals("Key", StringComparison.OrdinalIgnoreCase))
                    {
                        if (type.CanOpen)
                        {
                            using var result = OpenObject(entry, dir, GetMaximumAccess(GenericAccessRights.MaximumAllowed));
                            if (result.IsSuccess)
                            {
                                DumpObject(tokens, type_filter, access_rights, result.Result, false);
                            }
                            else
                            {
                                WriteAccessWarning(dir, entry.Name, result.Status);
                            }
                        }
                        else
                        {
                            WriteVerbose($@"Can't open {dir.FullPath}\{entry.Name} with type {entry.NtTypeName}");
                        }
                    }
                }
            }
        }
    }

    private NtResult<NtObject> OpenObject(ObjectDirectoryInformation entry, NtObject root, AccessMask desired_access)
    {
        NtType type = entry.NtType;
        using var obja = new ObjectAttributes(entry.Name, GetAttributeFlags(), root);
        return type.Open(obja, desired_access, false);
    }

    private NtResult<NtDirectory> OpenDirectory(string path, NtObject root)
    {
        using ObjectAttributes obja = new(path, GetAttributeFlags(), root);
        var result = NtDirectory.Open(obja, GetMaximumAccessGeneric(DirectoryAccessRights.Query | DirectoryAccessRights.ReadControl), false);
        if (result.IsSuccess || result.Status != NtStatus.STATUS_ACCESS_DENIED)
        {
            return result;
        }

        // Try again with just Query, if we can't even do this we give up.
        return NtDirectory.Open(obja, GetMaximumAccessGeneric(DirectoryAccessRights.Query), false);
    }

    /// <summary>
    /// Convert a Win32 Path to a Native NT path.
    /// </summary>
    /// <param name="win32_path">The win32 path to convert.</param>
    /// <returns>The native path.</returns>
    protected override string ConvertWin32Path(string win32_path)
    {
        string base_path = win32_path.TrimStart('\\');
        if (string.IsNullOrEmpty(base_path))
        {
            base_path = _base_named_objects;
        }
        else
        {
            base_path = $@"{_base_named_objects}\{base_path}";
        }
        return base_path;
    }

    private protected override void RunAccessCheckPath(IEnumerable<TokenEntry> tokens, string path)
    {
        using var result = OpenDirectory(path, null);
        if (result.IsSuccess)
        {
            if (FollowPath(result.Result.FullPath))
            {
                DumpDirectory(tokens, GetTypeFilter(), Access, result.Result, GetMaxDepth());
            }
        }
        else
        {
            using var obj = NtObject.OpenWithType(null, path, null, GetAttributeFlags(),
                GetMaximumAccess(GenericAccessRights.MaximumAllowed), null, false);
            if (obj.IsSuccess)
            {
                DumpObject(tokens, GetTypeFilter(), Access, obj.Result, false);
            }
        }
    }

    private void CheckHandles(IEnumerable<TokenEntry> tokens, HashSet<string> type_filter, 
        HashSet<ulong> checked_objects, NtProcess process, IEnumerable<NtHandle> handles)
    {
        foreach (NtHandle handle in handles)
        {
            if (Stopping)
            {
                return;
            }

            if (!IsTypeFiltered(handle.ObjectType, type_filter))
            {
                continue;
            }

            using var obj = NtGeneric.DuplicateFrom(process, new IntPtr(handle.Handle), 0, DuplicateObjectOptions.SameAccess, false);
            // We double check type here to ensure we've duplicated a valid handle handle.
            if (!obj.IsSuccess || !IsTypeFiltered(obj.Result.NtTypeName, type_filter))
            {
                continue;
            }

            if (checked_objects.Add(handle.Object))
            {
                if (CheckUnnamed || !string.IsNullOrEmpty(GetObjectName(obj.Result)))
                {
                    DumpObject(tokens, type_filter, Access, obj.Result,
                        obj.Result.NtTypeName.Equals("Directory", StringComparison.OrdinalIgnoreCase));
                }
            }
        }
    }

    private HashSet<string> GetTypeFilter()
    {
        return new HashSet<string>(TypeFilter ?? new string[0], StringComparer.OrdinalIgnoreCase);
    }

    private void RunAccessCheckHandles(IEnumerable<TokenEntry> tokens)
    {
        var type_filter = GetTypeFilter();
        using (NtToken process_token = NtToken.OpenProcessToken())
        {
            if (!process_token.SetPrivilege(TokenPrivilegeValue.SeDebugPrivilege, PrivilegeAttributes.Enabled))
            {
                WriteWarning("Current process doesn't have SeDebugPrivilege, results may be inaccurate");
            }
        }

        if (type_filter.Count == 0)
        {
            WriteWarning("Checking handle access without any type filtering can hang. Specify the types using -TypeFilter.");
        }

        HashSet<ulong> checked_objects = new();
        var handles = NtSystemInfo.GetHandles(-1, false).Where(h => IsTypeFiltered(h.ObjectType, type_filter)).GroupBy(h => h.ProcessId);
        
        foreach (var group in handles)
        {
            if (Stopping)
            {
                return;
            }

            using var proc = NtProcess.Open(group.Key, ProcessAccessRights.DupHandle, false);
            if (proc.IsSuccess)
            {
                CheckHandles(tokens, type_filter, checked_objects, proc.Result, group);
            }
        }
    }

    private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
    {
        if (FromHandle)
        {
            RunAccessCheckHandles(tokens);
        }
        else
        {
            base.RunAccessCheck(tokens);
        }
    }
}
