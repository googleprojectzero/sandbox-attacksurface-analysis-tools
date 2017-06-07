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
    ///   <para>Check accessible keys HKEY_LOCAL_MACHINE\Software for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleKey \Registry\Machine\Software -ProcessIds 1234,5678</code>
    ///   <para>Check accessible keys HKEY_LOCAL_MACHINE\Software for the process tokens of PIDs 1234 and 5678</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleKey \Registry\Machine\Software -Recurse</code>
    ///   <para>Check recursively for accessible keys HKEY_LOCAL_MACHINE\Software for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleKey HKLM\Software -Win32Path -Recurse</code>
    ///   <para>Check recursively for accessible keys NT path HKEY_LOCAL_MACHINE for the current process token using a Win32 path.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleKey HKCU -Recurse -Tokens $token -AccessRights GenericWrite</code>
    ///   <para>Get all keys with can be written to in HKEY_CURRENT_USER by a low integrity copy of current token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleFile")]
    public class GetAccessibleFileCmdlet : CommonAccessBaseCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the file path to check. Must be native form (such as \??\C:\Blah) unless -Win32Path is set.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public string Path { get; set; }

        /// <summary>
        /// <para type="description">Specify the file path is in a Win32 format (such as C:\Blah).</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Win32Path { get; set; }

        /// <summary>
        /// <para type="description">Specify a set of access rights which the file must at least be accessible for to count as an access.</para>
        /// </summary>
        [Parameter]
        public FileAccessRights AccessRights { get; set; }

        /// <summary>
        /// <para type="description">Specify a set of directory access rights which the file must at least be accessible for to count as an access.</para>
        /// </summary>
        [Parameter]
        public FileDirectoryAccessRights DirectoryAccessRights { get; set; }

        /// <summary>
        /// <para type="description">Specify whether to recursively check the file for subdirectories to access.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Recurse { get; set; }

        private static NtStatus OpenFile(string name, NtFile root, bool win32_path, FileOpenOptions options, out NtFile file)
        {
            if (win32_path)
            {
                name = NtFileUtils.DosFileNameToNt(name);
            }

            using (ObjectAttributes obja = new ObjectAttributes(name,
                AttributeFlags.CaseInsensitive, root))
            {
                NtStatus status = NtFile.Open(obja, FileAccessRights.ReadAttributes | FileAccessRights.ReadControl, 
                    FileShareMode.Read | FileShareMode.Delete, options, out file);
                if (status.IsSuccess() || status != NtStatus.STATUS_ACCESS_DENIED)
                {
                    return status;
                }

                // Try again with just ReadAttributes, if we can't even do this we give up.
                return NtFile.Open(obja, FileAccessRights.ReadAttributes,
                    FileShareMode.Read | FileShareMode.Delete, options, out file);
            }
        }

        private void CheckAccess(TokenEntry token, NtFile file, AccessMask access_rights, SecurityDescriptor sd)
        {
            NtType type = file.NtType;
            AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, type.GenericMapping);
            if (!granted_access.IsEmpty && granted_access.IsAllAccessGranted(access_rights))
            {
                WriteAccessCheckResult(file.FullPath, type.Name, granted_access, type.GenericMapping,
                    sd.ToSddl(), file.IsDirectory ? typeof(FileDirectoryAccessRights) : typeof(FileAccessRights), token.Information);
            }
        }

        private void CheckAccessUnderImpersonation(TokenEntry token, NtFile file)
        {
            NtFile new_file = null;
            try
            {
                NtStatus status = token.Token.RunUnderImpersonate(() => 
                    file.ReOpen(FileAccessRights.MaximumAllowed, 
                    FileShareMode.Read | FileShareMode.Delete, 
                    FileOpenOptions.None, out new_file));

                if (status.IsSuccess())
                {
                    WriteAccessCheckResult(file.FullPath, file.NtType.Name, new_file.GrantedAccessMask, 
                        file.NtType.GenericMapping, String.Empty, file.IsDirectory ? 
                        typeof(FileDirectoryAccessRights) : typeof(FileAccessRights), token.Information);
                }
            }
            finally
            {
                new_file?.Dispose();
            }
        }

        private void DumpFile(IEnumerable<TokenEntry> tokens, AccessMask access_rights, NtFile file)
        {
            if (file.IsAccessGranted(FileAccessRights.ReadControl))
            {
                SecurityDescriptor sd = file.SecurityDescriptor;
                foreach (var token in tokens)
                {
                    CheckAccess(token, file, access_rights, sd);
                }
            }
            else
            {
                // If we can't read security descriptor then try opening the key.
                foreach (var token in tokens)
                {
                    CheckAccessUnderImpersonation(token, file);
                }
            }
        }

        private void DumpDirectory(IEnumerable<TokenEntry> tokens, AccessMask access_rights, NtFile file, FileOpenOptions options)
        {
            if (Stopping)
            {
                return;
            }

            if (Recurse)
            {
                NtFile dir = null;

                try
                {
                    if (file.ReOpen(FileAccessRights.ReadData, FileShareMode.Read | FileShareMode.Delete, options | FileOpenOptions.DirectoryFile, out dir).IsSuccess())
                    {
                        foreach (var entry in dir.QueryDirectoryInfo())
                        {
                            NtFile new_file;
                            if (OpenFile(String.Empty, dir, false, options, out new_file).IsSuccess())
                            DumpFile(tokens, access_rights, new_file);
                            if (file.IsDirectory)
                            {
                                DumpDirectory(tokens, access_rights, new_file, options);
                            }
                        }
                    }
                }
                finally
                {
                    dir?.Dispose();
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

            FileOpenOptions options = FileOpenOptions.OpenReparsePoint | (open_for_backup ? FileOpenOptions.OpenForBackupIntent : FileOpenOptions.None);
            NtType type = NtType.GetTypeByType<NtFile>();
            AccessMask access_rights = type.MapGenericRights(AccessRights) | type.MapGenericRights(DirectoryAccessRights);
            NtFile file = null;
            try
            {
                if (OpenFile(Path, null, Win32Path, options, out file).IsSuccess())
                {
                    DumpFile(tokens,
                        access_rights,
                        file);
                    if (file.IsDirectory)
                    {
                        DumpDirectory(tokens, access_rights, file, options);
                    }
                }
            }
            finally
            {
                file?.Dispose();
            }
        }
    }
}
