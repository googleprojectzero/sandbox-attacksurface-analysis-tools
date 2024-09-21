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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible;

internal class MaximumAccess
{
    public AccessMask Access { get; set; }
    public string SecurityDescriptor { get; set; }

    public MaximumAccess(AccessMask access, string sddl)
    {
        Access = access;
        SecurityDescriptor = sddl;
    }
}

/// <summary>
/// <para type="synopsis">Get a list of accessible handles from a specified token.</para>
/// <para type="description">This cmdlet enumerates all handles accessible from a specific token and
/// checks and determines what the maximum access rights are for that handle.</para>
/// </summary>
/// <remarks>For best results this command should be run as an administrator.</remarks>
/// <example>
///   <code>Get-AccessibleHandle</code>
///   <para>Check all accessible handles for the current process token.</para>
/// </example>
/// <example>
///   <code>Get-AccessibleHandle -TypeFilter Key</code>
///   <para>Check all accessible key handles for the current process token.</para>
/// </example>
/// <example>
///   <code>Get-AccessibleHandle -ProcessIds 1234,5678</code>
///   <para>>Check all accessible handles for the process tokens of PIDs 1234 and 5678</para>
/// </example>
/// <example>
///   <code>Get-AccessibleHandle | Where-Object DifferentAccess</code>
///   <para>Check all accessible handles for the current process token where the access differs
///   from what the access would be if you reopened the resource</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "AccessibleHandle")]
[OutputType(typeof(HandleAccessCheckResult))]
public class GetAccessibleHandle : CommonAccessBaseCmdlet
{
    /// <summary>
    /// <para type="description">Specify list of NT object types to filter on.</para>
    /// </summary>
    [Parameter]
    public string[] TypeFilter { get; set; }

    /// <summary>
    /// <para type="description">Specify to query all file device paths. Doing this might cause the cmdlet to hang.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter QueryAllDevicePaths { get; set; }

    private HashSet<string> GetTypeFilter()
    {
        return new HashSet<string>(TypeFilter ?? new string[0], StringComparer.OrdinalIgnoreCase);
    }

    private static bool IsTypeFiltered(string type_name, HashSet<string> type_filter)
    {
        if (type_filter.Count > 0)
        {
            return type_filter.Contains(type_name);
        }
        return true;
    }

    private static NtResult<NtObject> ReopenUnderImpersonation(TokenEntry token, NtType type, NtObject obj)
    {
        using ObjectAttributes obj_attributes = new(string.Empty,
           AttributeFlags.CaseInsensitive, obj);
        return token.Token.RunUnderImpersonate(() => type.Open(obj_attributes, GenericAccessRights.MaximumAllowed, false));
    }

    private string GetObjectName(NtObject obj)
    {
        try
        {
            if (!QueryAllDevicePaths)
            {
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

    private MaximumAccess GetMaxAccess(TokenEntry token, NtObject obj, ulong obj_address, Dictionary<ulong, MaximumAccess> max_access)
    {
        if (max_access.ContainsKey(obj_address))
        {
            return max_access[obj_address];
        }

        NtType type = obj.NtType;
        if (!type.SecurityRequired && string.IsNullOrEmpty(GetObjectName(obj)))
        {
            max_access[obj_address] = new MaximumAccess(type.GenericMapping.GenericAll, string.Empty);
            return max_access[obj_address];
        }

        var result = obj.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
        if (!result.IsSuccess && !obj.IsAccessMaskGranted(GenericAccessRights.ReadControl))
        {
            // Try and duplicate handle to see if we can just ask for ReadControl.
            using var dup_obj = obj.DuplicateObject(GenericAccessRights.ReadControl, AttributeFlags.None,
                DuplicateObjectOptions.None, false);
            if (dup_obj.IsSuccess)
            {
                result = dup_obj.Result.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
            }
        }

        MaximumAccess access = null;
        if (result.IsSuccess)
        {
            access = new MaximumAccess(NtSecurity.GetMaximumAccess(result.Result, token.Token, type.GenericMapping), result.Result.ToSddl());
        }
        else if (type.CanOpen)
        {
            using var new_obj = ReopenUnderImpersonation(token, type, obj);
            if (new_obj.IsSuccess)
            {
                access = new MaximumAccess(new_obj.Result.GrantedAccessMask, string.Empty);
            }
        }

        max_access[obj_address] = access;
        return access;
    }

    private void CheckHandles(TokenEntry token, HashSet<string> type_filter,
        Dictionary<ulong, MaximumAccess> max_access, NtProcess process, IEnumerable<NtHandle> handles)
    {
        foreach (NtHandle handle in handles)
        {
            if (Stopping)
            {
                return;
            }

            using var result = NtGeneric.DuplicateFrom(process, new IntPtr(handle.Handle), 0, DuplicateObjectOptions.SameAccess, false);
            if (!result.IsSuccess)
            {
                continue;
            }

            using NtObject obj = result.Result.ToTypedObject();
            NtType type = obj.NtType;
            if (!IsTypeFiltered(type.Name, type_filter))
            {
                continue;
            }

            string full_path = GetObjectName(obj);

            MaximumAccess maximum_access = GetMaxAccess(token, obj, handle.Object, max_access);
            HandleAccessCheckResult access = new(maximum_access, handle,
                full_path, type.Name, handle.GrantedAccess, type.GenericMapping,
                maximum_access != null ? maximum_access.SecurityDescriptor : string.Empty, type.AccessRightsType, false, token.Information);
            WriteObject(access);
        }
    }

    private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
    {
        var type_filter = GetTypeFilter();
        if (QueryAllDevicePaths)
        {
            WriteWarning("Querying all device paths can result in hanging. Use with caution.");
        }

        var handles = NtSystemInfo.GetHandles(-1, false).Where(h => IsTypeFiltered(h.ObjectType, type_filter)).GroupBy(h => h.ProcessId);
        foreach (TokenEntry token in tokens)
        {
            var max_access = new Dictionary<ulong, MaximumAccess>();
            foreach (var group in handles)
            {
                if (Stopping)
                {
                    return;
                }

                using var proc = token.Token.RunUnderImpersonate(() => NtProcess.Open(group.Key, ProcessAccessRights.DupHandle, false));
                if (proc.IsSuccess)
                {
                    CheckHandles(token, type_filter, max_access, proc.Result, group);
                }
            }
        }
    }
}
