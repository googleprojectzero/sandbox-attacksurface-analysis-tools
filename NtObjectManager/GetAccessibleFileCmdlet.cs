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
    /// Enumeration to determine what to check.
    /// </summary>
    public enum FileCheckMode
    {
        /// <summary>
        /// Check files and directories for access.
        /// </summary>
        All,
        /// <summary>
        /// Check files only.
        /// </summary>
        FilesOnly,
        /// <summary>
        /// Check directories only.
        /// </summary>
        DirectoriesOnly        
    }

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
    public class GetAccessibleFileCmdlet : GetAccessiblePathCmdlet
    {
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
        /// <para type="description">Limit access check to specific types of files.</para>
        /// </summary>
        [Parameter]
        public FileCheckMode CheckMode { get; set; }

        private static NtResult<NtFile> OpenFile(string name, NtFile root, bool win32_path, FileOpenOptions options)
        {
            if (win32_path)
            {
                name = NtFileUtils.DosFileNameToNt(name);
            }

            using (ObjectAttributes obja = new ObjectAttributes(name,
                AttributeFlags.CaseInsensitive, root))
            {
                var result = NtFile.Open(obja, FileAccessRights.Synchronize | FileAccessRights.ReadAttributes | FileAccessRights.ReadControl,
                    FileShareMode.Read | FileShareMode.Delete, options | FileOpenOptions.SynchronousIoNonAlert, false);
                if (result.IsSuccess || result.Status != NtStatus.STATUS_ACCESS_DENIED)
                {
                    return result;
                }

                // Try again with just ReadAttributes, if we can't even do this we give up.
                return NtFile.Open(obja, FileAccessRights.Synchronize | FileAccessRights.ReadAttributes,
                    FileShareMode.Read | FileShareMode.Delete, options | FileOpenOptions.SynchronousIoNonAlert, false);
            }
        }

        private static bool IsDirectoryNoThrow(NtFile file)
        {
            try
            {
                return file.IsDirectory;
            }
            catch (NtException)
            {
                return false;
            }
        }

        private void CheckAccess(TokenEntry token, NtFile file, AccessMask access_rights, SecurityDescriptor sd)
        {
            NtType type = file.NtType;
            AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, type.GenericMapping);
            if (!granted_access.IsEmpty && granted_access.IsAllAccessGranted(access_rights))
            {
                WriteAccessCheckResult(Win32Path ? file.Win32PathName : file.FullPath, type.Name, granted_access, type.GenericMapping,
                    sd.ToSddl(), IsDirectoryNoThrow(file) ? typeof(FileDirectoryAccessRights) : typeof(FileAccessRights), token.Information);
            }
        }

        private void CheckAccessUnderImpersonation(TokenEntry token, NtFile file)
        {
            using (var result = token.Token.RunUnderImpersonate(() =>
                 file.ReOpen(FileAccessRights.MaximumAllowed,
                 FileShareMode.Read | FileShareMode.Delete,
                 FileOpenOptions.None, false)))
            {
                if (result.Status.IsSuccess())
                {
                    WriteAccessCheckResult(file.FullPath, file.NtType.Name, result.Result.GrantedAccessMask,
                        file.NtType.GenericMapping, String.Empty, IsDirectoryNoThrow(file) ?
                        typeof(FileDirectoryAccessRights) : typeof(FileAccessRights), token.Information);
                }
            }
        }

        private void DumpFile(IEnumerable<TokenEntry> tokens, AccessMask access_rights, NtFile file)
        {
            bool directory = IsDirectoryNoThrow(file);
            if (CheckMode != FileCheckMode.All)
            {
                if ((CheckMode == FileCheckMode.FilesOnly && directory) ||
                    (CheckMode == FileCheckMode.DirectoriesOnly && !directory))
                {
                    return;
                }
            }

            var result = file.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
            if (result.IsSuccess)
            {
                foreach (var token in tokens)
                {
                    CheckAccess(token, file, access_rights, result.Result);
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

        private void DumpDirectory(IEnumerable<TokenEntry> tokens, AccessMask access_rights, NtFile file, FileOpenOptions options, int current_depth)
        {
            if (Stopping || current_depth <= 0)
            {
                return;
            }

            if (Recurse)
            {
                using (var result = file.ReOpen(FileAccessRights.Synchronize | FileAccessRights.ReadData | FileAccessRights.ReadAttributes, 
                    FileShareMode.Read | FileShareMode.Delete, options | FileOpenOptions.DirectoryFile | FileOpenOptions.SynchronousIoNonAlert, false))
                {
                    if (result.Status.IsSuccess())
                    {
                        foreach (var entry in result.Result.QueryDirectoryInfo())
                        {
                            if (CheckMode == FileCheckMode.DirectoriesOnly && !entry.IsDirectory)
                            {
                                continue;
                            }

                            NtFile base_file = result.Result;
                            string filename = entry.FileName;
                            if (filename.Contains(@"\"))
                            {
                                filename = base_file.FullPath + filename;
                                base_file = null;
                            }
                            
                            using (var new_file = OpenFile(filename, base_file, false, options))
                            {
                                if (new_file.IsSuccess)
                                {
                                    DumpFile(tokens, access_rights, new_file.Result);
                                    if (IsDirectoryNoThrow(new_file.Result))
                                    {
                                        DumpDirectory(tokens, access_rights, new_file.Result, options, current_depth - 1);
                                    }
                                }
                            }
                        }
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

            if (!Path.StartsWith(@"\") && !Win32Path)
            {
                WriteWarning("Path doesn't start with \\. You should specify -Win32Path to use a non-NT path for the file.");
            }

            FileOpenOptions options = FileOpenOptions.OpenReparsePoint | (open_for_backup ? FileOpenOptions.OpenForBackupIntent : FileOpenOptions.None);
            NtType type = NtType.GetTypeByType<NtFile>();
            AccessMask access_rights = type.MapGenericRights(AccessRights) | type.MapGenericRights(DirectoryAccessRights);
            using (var result = OpenFile(Path, null, Win32Path, options))
            {
                if (result.IsSuccess)
                {
                    DumpFile(tokens,
                        access_rights,
                        result.Result);
                    if (IsDirectoryNoThrow(result.Result))
                    {
                        DumpDirectory(tokens, access_rights, result.Result, options, GetMaxDepth());
                    }
                }
            }
        }
    }
}
