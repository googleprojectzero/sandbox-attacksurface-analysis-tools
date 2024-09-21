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
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="synopsis">Get a list of named pipes that can be opened by a specified token.</para>
/// <para type="description">This cmdlet checks for named pipes and tries to determine
/// if one or more specified tokens can open them. If no tokens are specified the current process
/// token is used.</para>
/// </summary>
/// <example>
///   <code>Get-AccessibleNamedPipe</code>
///   <para>Check accessible named pipes for the current process token.</para>
/// </example>
/// <example>
///   <code>Get-AccessibleNamedPipe -OpenServer</code>
///   <para>Check accessible named pipes server end points which can be opened for the current process token.</para>
/// </example>
/// <example>
///   <code>Get-AccessibleNamedPipe -ProcessIds 1234,5678</code>
///   <para>Check accessible named pipes for the process tokens of PIDs 1234 and 5678</para>
/// </example>
/// <example>
///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleNamedPipes -Tokens $token -AccessRights GenericWrite</code>
///   <para>Get all named pipes with can be written to by a low integrity copy of current token.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "AccessibleNamedPipe")]
[OutputType(typeof(CommonAccessCheckResult))]
public class GetAccessibleNamedPipeCmdlet : CommonAccessBaseWithAccessCmdlet<FileAccessRights>
{
    private static readonly NtType _file_type = NtType.GetTypeByType<NtFile>();

    /// <summary>
    /// <para type="description">When generating the results format path in Win32 format.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter FormatWin32Path { get; set; }

    /// <summary>
    /// <para type="description">Try and open the server end rather than the client end of the pipe.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter OpenServer { get; set; }

    const string NamedPipeBasePath = @"\Device\NamedPipe\";

    private static NtResult<NtFile> OpenFile(string name, FileAccessRights desired_access, bool open_server)
    {
        using ObjectAttributes obja = new(NamedPipeBasePath + name,
            AttributeFlags.CaseInsensitive, null);
        if (open_server)
        {
            return NtFile.CreateNamedPipe(obja, desired_access | FileAccessRights.Synchronize,
                FileShareMode.Read | FileShareMode.Write, FileOpenOptions.SynchronousIoNonAlert,
                FileDisposition.Open, NamedPipeType.Bytestream, NamedPipeReadMode.ByteStream,
                NamedPipeCompletionMode.CompleteOperation, 0, 0, 0, NtWaitTimeout.FromMilliseconds(0), false).Cast<NtFile>();

        }
        else
        {
            return NtFile.Open(obja, desired_access,
                FileShareMode.Read | FileShareMode.Write, FileOpenOptions.None, false);
        }
    }

    private static string FormatPath(string path, bool win32_path)
    {
        return $"{(win32_path ? @"\\.\pipe\" : NamedPipeBasePath)}{path}";
    }

    private void CheckAccess(TokenEntry token, AccessMask access_rights, string path, NtFile file)
    {
        var sd = file.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
        if (!sd.IsSuccess)
        {
            return;
        }

        AccessMask granted_access = NtSecurity.GetMaximumAccess(sd.Result, 
            token.Token, _file_type.GenericMapping);
        if (IsAccessGranted(granted_access, access_rights))
        {
            WriteAccessCheckResult(FormatPath(path, FormatWin32Path), "NamedPipe",
                granted_access, _file_type.GenericMapping,
                sd.Result, typeof(FileAccessRights), false, token.Information);
        }
    }

    private void CheckAccessUnderImpersonation(TokenEntry token, AccessMask access_rights, string path)
    {
        using var result = token.Token.RunUnderImpersonate(() =>
             OpenFile(path, FileAccessRights.MaximumAllowed, OpenServer));
        if (result.Status.IsSuccess())
        {
            if (IsAccessGranted(result.Result.GrantedAccessMask, access_rights))
            {
                WriteAccessCheckResult(FormatPath(path, FormatWin32Path), "NamedPipe", result.Result.GrantedAccessMask,
                   _file_type.GenericMapping, null, typeof(FileAccessRights), false,
                    token.Information);
            }
        }
        else
        {
            WriteAccessWarning(FormatPath(path, FormatWin32Path), result.Status);
        }
    }

    private void DumpFile(IEnumerable<TokenEntry> tokens, AccessMask access_rights, string path)
    {
        using var result = OpenFile(path, FileAccessRights.ReadControl, OpenServer);
        if (result.IsSuccess)
        {
            foreach (var token in tokens)
            {
                CheckAccess(token, access_rights, path, result.Result);
            }
        }
        else
        {
            foreach (var token in tokens)
            {
                CheckAccessUnderImpersonation(token, access_rights, path);
            }
        }
    }

    private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
    {
        NtType type = NtType.GetTypeByType<NtFile>();
        AccessMask access_rights = type.MapGenericRights(Access);
        using var result = OpenFile("",
            FileAccessRights.ReadData, false);
        NtFile file = result.Result;
        foreach (var entry in result.Result.QueryDirectoryInfo())
        {
            DumpFile(tokens, access_rights, entry.FileName);
        }
    }
}
