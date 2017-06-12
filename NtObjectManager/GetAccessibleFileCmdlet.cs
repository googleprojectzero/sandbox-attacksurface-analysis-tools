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
    /// <para type="description">Limit access check to specific types of files.</para>
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
    /// <para type="synopsis">Get a list of files that can be opened by a specified token.</para>
    /// <para type="description">This cmdlet checks a file or directory and tries to determine
    /// if one or more specified tokens can open them. If no tokens are specified the current process
    /// token is used.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-AccessibleFile \??\C:\Windows</code>
    ///   <para>Check accessible file c:\Windows for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleFile \??\C:\Windows -ProcessIds 1234,5678</code>
    ///   <para>Check accessible file c:\Windows for the process tokens of PIDs 1234 and 5678</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleFile \??\C:\Windows -Recurse</code>
    ///   <para>Check recursively for check accessible files under c:\Windows for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleFile -Win32Path C:\Windows -Recurse</code>
    ///   <para>Check recursively for check accessible files under c:\Windows for the current process token using a Win32 path.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleFile -Win32Path C:\Windows -Recurse -MaxDepth 2</code>
    ///   <para>Check recursively for check accessible files under c:\Windows for the current process token using a Win32 path with a max depth of 2.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleFile \??\C:\Windows -Recurse -Tokens $token -AccessRights GenericWrite</code>
    ///   <para>Get all files with can be written to \??\C:\Windows by a low integrity copy of current token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleFile")]
    [OutputType(typeof(AccessCheckResult))]
    public class GetAccessibleFileCmdlet : GetAccessiblePathCmdlet<FileAccessRights>
    {
        /// <summary>
        /// <para type="description">Specify a set of directory access rights which a directory must at least be accessible for to count as an access.</para>
        /// </summary>
        [Parameter]
        public FileDirectoryAccessRights DirectoryAccessRights { get; set; }

        /// <summary>
        /// <para type="description">Limit access check to specific types of files.</para>
        /// </summary>
        [Parameter]
        public FileCheckMode CheckMode { get; set; }

        private static NtResult<NtFile> OpenFile(string name, NtFile root, FileOpenOptions options)
        {
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

        private void CheckAccess(TokenEntry token, NtFile file, AccessMask access_rights, SecurityDescriptor sd, SecurityDescriptor parent_sd)
        {
            NtType type = file.NtType;
            AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, type.GenericMapping);

            // Determine if the parent gives additonal rights to this file.
            if (!granted_access.IsAllAccessGranted(FileDirectoryAccessRights.ListDirectory | FileDirectoryAccessRights.Delete) && parent_sd != null)
            {
                AccessMask parent_granted_access = NtSecurity.GetMaximumAccess(parent_sd, token.Token, type.GenericMapping);
                if (parent_granted_access.IsAccessGranted(FileDirectoryAccessRights.DeleteChild))
                {
                    granted_access |= FileAccessRights.Delete;
                }
                if (parent_granted_access.IsAccessGranted(FileDirectoryAccessRights.ListDirectory))
                {
                    granted_access |= FileAccessRights.ReadAttributes;
                }
            }

            if (IsAccessGranted(granted_access, access_rights))
            {
                bool is_directory = IsDirectoryNoThrow(file);
                WriteAccessCheckResult(FormatWin32Path ? file.Win32PathName : file.FullPath, type.Name, granted_access, type.GenericMapping,
                    sd.ToSddl(), is_directory ? typeof(FileDirectoryAccessRights) : typeof(FileAccessRights), is_directory, token.Information);
            }
        }

        private void CheckAccessUnderImpersonation(TokenEntry token, AccessMask access_rights, NtFile file)
        {
            using (var result = token.Token.RunUnderImpersonate(() =>
                 file.ReOpen(FileAccessRights.MaximumAllowed,
                 FileShareMode.Read | FileShareMode.Delete,
                 FileOpenOptions.None, false)))
            {
                if ( result.Status.IsSuccess() && IsAccessGranted(result.Result.GrantedAccessMask, access_rights))
                {
                    bool is_directory = IsDirectoryNoThrow(result.Result);
                    WriteAccessCheckResult(file.FullPath, file.NtType.Name, result.Result.GrantedAccessMask,
                        file.NtType.GenericMapping, String.Empty, is_directory ?
                        typeof(FileDirectoryAccessRights) : typeof(FileAccessRights), is_directory, token.Information);
                }
            }
        }

        private void DumpFile(IEnumerable<TokenEntry> tokens, AccessMask access_rights, AccessMask dir_access_rights, SecurityDescriptor parent_sd, NtFile file)
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
            AccessMask desired_access = directory ? dir_access_rights : access_rights;

            var result = file.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
            if (result.IsSuccess)
            {
                foreach (var token in tokens)
                {
                    CheckAccess(token, file, desired_access, result.Result, parent_sd);
                }
            }
            else
            {
                // If we can't read security descriptor then try opening the key.
                foreach (var token in tokens)
                {
                    CheckAccessUnderImpersonation(token, desired_access, file);
                }
            }
        }

        private void DumpDirectory(IEnumerable<TokenEntry> tokens, AccessMask access_rights, 
            AccessMask dir_access_rights, NtFile file, FileOpenOptions options, int current_depth)
        {
            if (Stopping || current_depth <= 0)
            {
                return;
            }

            var parent_sd = file.GetSecurityDescriptor(SecurityInformation.AllBasic, false);

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
                            
                            using (var new_file = OpenFile(filename, base_file, options))
                            {
                                if (new_file.IsSuccess)
                                {
                                    DumpFile(tokens, access_rights, dir_access_rights, 
                                        parent_sd.IsSuccess ? parent_sd.Result : null, new_file.Result);
                                    if (IsDirectoryNoThrow(new_file.Result))
                                    {
                                        DumpDirectory(tokens, access_rights, dir_access_rights, 
                                            new_file.Result, options, current_depth - 1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Convert a Win32 Path to a Native NT path.
        /// </summary>
        /// <param name="win32_path">The win32 path to convert.</param>
        /// <returns>The native path.</returns>
        protected override string ConvertWin32Path(string win32_path)
        {
            return NtFileUtils.DosFileNameToNt(win32_path);
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

        internal override void RunAccessCheckPath(IEnumerable<TokenEntry> tokens, string path)
        {
            FileOpenOptions options = FileOpenOptions.OpenReparsePoint | (_open_for_backup ? FileOpenOptions.OpenForBackupIntent : FileOpenOptions.None);
            NtType type = NtType.GetTypeByType<NtFile>();
            AccessMask access_rights = type.MapGenericRights(AccessRights);
            AccessMask dir_access_rights = type.MapGenericRights(DirectoryAccessRights);
            using (var result = OpenFile(path, null, options))
            {
                NtFile file = result.GetResultOrThrow();
                DumpFile(tokens,
                    access_rights,
                    dir_access_rights,
                    null,
                    result.Result);
                if (IsDirectoryNoThrow(result.Result))
                {
                    DumpDirectory(tokens, access_rights, dir_access_rights, file, options, GetMaxDepth());
                }
            }
        }
    }
}
