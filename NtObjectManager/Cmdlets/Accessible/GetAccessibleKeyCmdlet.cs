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
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="synopsis">Get a list of Registry Keys that can be opened by a specified token.</para>
/// <para type="description">This cmdlet checks a registry key and tries to determine
/// if one or more specified tokens can open them. If no tokens are specified the current process
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
///   <code>Get-AccessibleKey \Registry\Machine\Software -Recurse -MaxDepth 5</code>
///   <para>Check recursively for accessible keys \Registry\Machine\Software for the current process token to a maximum depth of 5.</para>
/// </example>
/// <example>
///   <code>Get-AccessibleKey -Win32Path HKLM\Software -Recurse</code>
///   <para>Check recursively for accessible keys NT path HKEY_LOCAL_MACHINE for the current process token using a Win32 path.</para>
/// </example>
/// <example>
///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleKey -Win32Path HKCU -Recurse -Tokens $token -AccessRights GenericWrite</code>
///   <para>Get all keys with can be written to in HKEY_CURRENT_USER by a low integrity copy of current token.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "AccessibleKey")]
[OutputType(typeof(CommonAccessCheckResult))]
public class GetAccessibleKeyCmdlet : GetAccessiblePathCmdlet<KeyAccessRights>
{
    private NtResult<NtKey> OpenKey(string name, NtObject root, bool open_link, bool open_for_backup)
    {
        AttributeFlags flags = GetAttributeFlags();
        if (open_link)
        {
            flags |= AttributeFlags.OpenLink;
        }

        using ObjectAttributes obja = new(name,
            flags, root);
        return NtKey.Open(obja, GetMaximumAccess(KeyAccessRights.MaximumAllowed),
            open_for_backup ? KeyCreateOptions.BackupRestore : KeyCreateOptions.NonVolatile, false);
    }

    private void CheckAccess(TokenEntry token, NtKey key, AccessMask access_rights, SecurityDescriptor sd)
    {
        NtType type = key.NtType;
        AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, type.GenericMapping);
        if (IsAccessGranted(granted_access, access_rights))
        {
            WriteAccessCheckResult(FormatWin32Path ? key.Win32Path : key.FullPath, type.Name, granted_access, type.GenericMapping, 
                sd, typeof(KeyAccessRights), true, token.Information);
        }
    }

    private void CheckAccessUnderImpersonation(TokenEntry token, AccessMask access_rights, NtKey key)
    {
        using ObjectAttributes obj_attributes = new(string.Empty,
            GetAttributeFlags() | (FollowLink ? AttributeFlags.None : AttributeFlags.OpenLink), key);
        using var result = token.Token.RunUnderImpersonate(() => NtKey.Open(obj_attributes, KeyAccessRights.MaximumAllowed, 0, false));
        if (result.IsSuccess && IsAccessGranted(result.Result.GrantedAccessMask, access_rights))
        {
            WriteAccessCheckResult(key.FullPath, key.NtType.Name, result.Result.GrantedAccessMask, key.NtType.GenericMapping,
                null, typeof(KeyAccessRights), true, token.Information);
        }
    }

    private void DumpKey(IEnumerable<TokenEntry> tokens, AccessMask access_rights, bool open_for_backup, NtKey key, int current_depth)
    {
        if (IncludePath(key.Name))
        {
            var sd = GetSecurityDescriptor(key);
            if (sd.IsSuccess)
            {
                foreach (var token in tokens)
                {
                    CheckAccess(token, key, access_rights, sd.Result);
                }
            }
            else
            {
                // If we can't read security descriptor then try opening the key.
                foreach (var token in tokens)
                {
                    CheckAccessUnderImpersonation(token, access_rights, key);
                }
            }
        }

        if (Stopping || current_depth <= 0)
        {
            return;
        }

        // Can never recurse predefined key handles so just ignore them.
        if (Recurse && key.IsAccessGranted(KeyAccessRights.EnumerateSubKeys) && !key.PredefinedHandle)
        {
            foreach (string subkey in key.QueryKeys())
            {
                if (FilterPath(subkey))
                {
                    continue;
                }
                using var result = OpenKey(subkey, key, !FollowLink, open_for_backup);
                if (result.IsSuccess)
                {
                    if (FollowPath(result.Result.FullPath))
                    {
                        DumpKey(tokens, access_rights, open_for_backup, result.Result, current_depth - 1);
                    }
                }
                else
                {
                    WriteAccessWarning($@"{key.FullPath}\{subkey}", result.Status);
                }
            }
        }
    }

    private bool _open_for_backup;

    /// <summary>
    /// Override for begin processing.
    /// </summary>
    protected override void BeginProcessing()
    {
        using (NtToken process_token = NtToken.OpenProcessToken())
        {
            _open_for_backup = process_token.SetPrivilege(TokenPrivilegeValue.SeBackupPrivilege, PrivilegeAttributes.Enabled);

            if (!_open_for_backup)
            {
                WriteWarning("Current process doesn't have SeBackupPrivilege, results may be inaccurate");
            }
        }

        base.BeginProcessing();
    }

    /// <summary>
    /// Convert a Win32 Path to a Native NT path.
    /// </summary>
    /// <param name="win32_path">The win32 path to convert.</param>
    /// <returns>The native path.</returns>
    protected override string ConvertWin32Path(string win32_path)
    {
        return NtKeyUtils.Win32KeyNameToNt(win32_path);
    }

    private protected override void RunAccessCheckPath(IEnumerable<TokenEntry> tokens, string path)
    {
        using var result = OpenKey(path, null, false, _open_for_backup);
        NtKey key = result.Result;
        if (FollowPath(key.FullPath))
        {
            DumpKey(tokens, result.Result.NtType.MapGenericRights(Access), _open_for_backup, key, GetMaxDepth());
        }
    }
}
