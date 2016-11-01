//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Provider;
using System.Security.AccessControl;
using System.Text.RegularExpressions;

namespace NtObjectManager
{
    /// <summary>
    /// Object manager provider.
    /// </summary>
    [CmdletProvider("NtObjectManager", ProviderCapabilities.ExpandWildcards)]
    public class NtObjectManagerProvider : NavigationCmdletProvider, ISecurityDescriptorCmdletProvider
    {
        private static Dictionary<string, NtDirectoryEntry> _item_cache = new Dictionary<string, NtDirectoryEntry>();

        private class ObjectManagerPSDriveInfo : PSDriveInfo
        {
            public ObjectManagerPSDriveInfo(NtDirectory root, PSDriveInfo drive_info) 
                : base(drive_info)
            {
                DirectoryRoot = root;
            }            

            public NtDirectory DirectoryRoot { get; private set; }
        }

        private string GetDrivePath()
        {
            if (PSDriveInfo == null)
            {
                return String.Empty;
            }

            return PSDriveInfo.Root;
        }

        private string PSPathToNT(string path)
        {
            return path.Replace('\u2044', '/');
        }

        private string NTPathToPS(string path)
        {
            return path.Replace('/', '\u2044');
        }

        /// <summary>
        /// Overridden method to initialize default drives.
        /// </summary>
        /// <returns>The list of default drives.</returns>
        protected override Collection<PSDriveInfo> InitializeDefaultDrives()
        {
            PSDriveInfo drive = new PSDriveInfo("NtObject", this.ProviderInfo, GLOBAL_ROOT, "NT Object Manager Root Directory", null);
            int session_id = Process.GetCurrentProcess().SessionId;
            string base_dir = null;
            if (session_id == 0)
            {
                base_dir = GLOBAL_ROOT + "BaseNamedObjects";
            }
            else
            {
                base_dir = String.Format(@"{0}Sessions\{1}\BaseNamedObjects", GLOBAL_ROOT, session_id);
            }

            PSDriveInfo session = new PSDriveInfo("SessionNtObject", this.ProviderInfo, 
                String.Format(base_dir, Process.GetCurrentProcess().SessionId), "Current Session NT Objects", null);
            Collection<PSDriveInfo> drives = new Collection<PSDriveInfo>() { drive, session };
            return drives;
        }

        const string GLOBAL_ROOT = @"nt:";
        const string NAMESPACE_ROOT = @"ntpriv:";

        /// <summary>
        /// Overridden method to create a new drive.
        /// </summary>
        /// <param name="drive">The template drive info.</param>
        /// <returns>The new drive info.</returns>
        protected override PSDriveInfo NewDrive(PSDriveInfo drive)
        {
            if (drive == null)
            {
                WriteError(new ErrorRecord(
                           new ArgumentNullException("drive"),
                           "NullDrive",
                           ErrorCategory.InvalidArgument,
                           null));

                return null;
            }

            if (String.IsNullOrWhiteSpace(drive.Root) && (!drive.Root.StartsWith(GLOBAL_ROOT) || !drive.Root.StartsWith(NAMESPACE_ROOT)))
            {
                WriteError(new ErrorRecord(
                           new ArgumentNullException("drive.Root"),
                           "InvalidRoot",
                           ErrorCategory.InvalidArgument,
                           null));

                return null;
            }

            try
            {
                if (drive.Root.StartsWith(NAMESPACE_ROOT))
                {
                    using (NtDirectory dir = NtDirectory.OpenPrivateNamespace(BoundaryDescriptor.CreateFromString(drive.Root.Substring(NAMESPACE_ROOT.Length))))
                    {
                        ObjectManagerPSDriveInfo objmgr_drive = new ObjectManagerPSDriveInfo(dir.Duplicate(), drive);
                        return objmgr_drive;
                    }
                }
                else
                {
                    using (NtDirectory root = NtDirectory.Open(@"\"))
                    {
                        using (NtDirectory dir = NtDirectory.Open(drive.Root.Substring(GLOBAL_ROOT.Length), root, DirectoryAccessRights.MaximumAllowed))
                        {
                            ObjectManagerPSDriveInfo objmgr_drive = new ObjectManagerPSDriveInfo(dir.Duplicate(), drive);
                            return objmgr_drive;
                        }
                    }
                }
            }
            catch (NtException ex)
            {
                WriteError(new ErrorRecord(
                ex,
                "NoRoot",
                ErrorCategory.PermissionDenied,
                drive));
                return null;
            }
        }

        /// <summary>
        /// Overridden method to remove a drive.
        /// </summary>
        /// <param name="drive">The drive to remove.</param>
        /// <returns>The removed drive.</returns>
        protected override PSDriveInfo RemoveDrive(PSDriveInfo drive)
        {
            if (drive == null)
            {
                WriteError(new ErrorRecord(
                           new ArgumentNullException("drive"),
                           "NullDrive",
                           ErrorCategory.InvalidArgument,
                           drive));

                return null;
            }

            ObjectManagerPSDriveInfo objmgr_drive = drive as ObjectManagerPSDriveInfo;
            if (objmgr_drive == null)
            {
                return null;
            }

            objmgr_drive.DirectoryRoot.Close();

            return objmgr_drive;
        }

        /// <summary>
        /// Overridden method to check if path is valid.
        /// </summary>
        /// <param name="path">The path to check.</param>
        /// <returns>True if the path is valid.</returns>
        protected override bool IsValidPath(string path)
        {
            if (String.IsNullOrEmpty(path))
            {
                return false;
            }

            path = GetRelativePath(PSPathToNT(path));
            string[] ps = path.Split('\\');

            foreach (string p in ps)
            {
                if (p.Length == 0)
                {
                    return false;
                }
            }
            return true;
        }

        private string GetRelativePath(string path)
        {
            // Remove extra path separators.
            path = path.TrimStart('\\');
            if (path.StartsWith(GetDrivePath(), StringComparison.OrdinalIgnoreCase))
            {
                return path.Substring(GetDrivePath().Length).Trim('\\');
            }
            return path;
        }

        private ObjectManagerPSDriveInfo GetDrive()
        {
            return (ObjectManagerPSDriveInfo)this.PSDriveInfo;
        }

        private NtDirectory GetPathDirectory(string path)
        {
            int last_slash = path.LastIndexOf('\\');
            if (last_slash == -1)
            {
                return GetDrive().DirectoryRoot.Duplicate();
            }
            else
            {
                NtDirectory dir = GetDrive().DirectoryRoot;
                string base_path = path.Substring(0, last_slash);
                
                return NtDirectory.Open(base_path,
                        dir, DirectoryAccessRights.MaximumAllowed);
            }
        }

        private NtDirectory GetDirectory(string path)
        {
            if (path.Length == 0)
            {
                return GetDrive().DirectoryRoot.Duplicate();
            }

            NtDirectory dir = GetDrive().DirectoryRoot;

            return NtDirectory.Open(path,
                dir, DirectoryAccessRights.MaximumAllowed);
        }

        private ObjectDirectoryInformation GetEntry(NtDirectory dir, string path)
        {
            int last_slash = path.LastIndexOf('\\');
            if (last_slash != -1)
            {
                path = path.Substring(last_slash + 1);
            }

            return dir.GetDirectoryEntry(path);
        }
        
        /// <summary>
        /// Overriden method to check if an item exists.
        /// </summary>
        /// <param name="path">The drive path to check.</param>
        /// <returns>True if the item exists.</returns>
        protected override bool ItemExists(string path)
        {
            bool exists = false;

            if (GetDrive() == null)
            {
                return false;
            }

            path = GetRelativePath(PSPathToNT(path));
            if (path.Length == 0)
            {
                return true;
            }
            
            try
            {
                using (NtDirectory dir = GetPathDirectory(path))
                {
                    exists = GetEntry(dir, path) != null;
                }
            }
            catch (NtException)
            {
            }

            // If we can't find it indirectly, at least see if there's a directory with this name.
            return exists || GetDrive().DirectoryRoot.DirectoryExists(path);
        }

        /// <summary>
        /// Overidden method to check if an item is a container.
        /// </summary>
        /// <param name="path">The drive path to check.</param>
        /// <returns>True if the item is a container.</returns>
        protected override bool IsItemContainer(string path)
        {
            bool is_container = false;

            if (GetDrive() == null)
            {
                return false;
            }

            path = GetRelativePath(PSPathToNT(path));
            // The root always exists.
            if (path.Length == 0)
            {
                return true;
            }

            try
            {
                using (NtDirectory dir = GetPathDirectory(path))
                {
                    ObjectDirectoryInformation dir_info = GetEntry(dir, path);
                    is_container = dir_info != null
                        && dir_info.TypeName.Equals("directory", StringComparison.OrdinalIgnoreCase);
                }
            }
            catch (NtException)
            {   
            }

            return is_container || GetDrive().DirectoryRoot.DirectoryExists(path); 
        }

        private string BuildDrivePath(string relative_path)
        {
            string drive_path = GetDrivePath();
            if (drive_path.Length == 0)
            {
                return relative_path;
            }
            else
            {
                return String.Format(@"{0}\{1}", drive_path, relative_path);
            }
        }

        private string BuildRelativePath(string relative_path, string name)
        {
            if (relative_path.Length == 0)
            {
                return name;
            }
            else
            {
                return String.Format(@"{0}\{1}", relative_path, name);
            }
        }

        private void GetChildItemsRecursive(string relative_path, bool recurse)
        {
            try
            {
                using (NtDirectory dir = GetDirectory(relative_path))
                {
                    Queue<string> dirs = new Queue<string>();
                    foreach (ObjectDirectoryInformation dir_info in dir.Query())
                    {
                        string new_path = BuildRelativePath(relative_path, dir_info.Name);
                        WriteItemObject(new NtDirectoryEntry(GetDrive().DirectoryRoot, new_path,
                            recurse ? new_path : dir_info.Name, dir_info.TypeName), NTPathToPS(BuildDrivePath(new_path)), dir_info.IsDirectory);
                        if (recurse && dir_info.IsDirectory)
                        {
                            dirs.Enqueue(new_path);
                        }
                    }

                    if (recurse && dirs.Count > 0)
                    {
                        foreach (string new_dir in dirs)
                        {
                            GetChildItemsRecursive(new_dir, recurse);
                        }
                    }
                }
            }
            catch (NtException)
            {
                if (!recurse)
                {
                    throw;
                }
            }
        }

        /// <summary>
        /// Overridden method to get the child items of a path.
        /// </summary>
        /// <param name="path">The drive path.</param>
        /// <param name="recurse">True if the path should be enumerated recursively.</param>
        protected override void GetChildItems(string path, bool recurse)
        {
            if (GetDrive() == null)
            {
                return;
            }

            string relative_path = GetRelativePath(PSPathToNT(path));

            GetChildItemsRecursive(relative_path, recurse);
        }

        /// <summary>
        /// Overridden method to get the child item names of a path.
        /// </summary>
        /// <param name="path">The drive path.</param>
        /// <param name="returnContainers">Return containers.</param>
        protected override void GetChildNames(string path, ReturnContainers returnContainers)
        {
            if (GetDrive() == null)
            {
                return;
            }

            string relative_path = GetRelativePath(PSPathToNT(path));

            using (NtDirectory dir = GetDirectory(relative_path))
            {
                foreach (ObjectDirectoryInformation dir_info in dir.Query())
                {
                    WriteItemObject(dir_info.Name, NTPathToPS(BuildDrivePath(BuildRelativePath(relative_path, dir_info.Name))), dir_info.IsDirectory);
                }
            }
        }

        /// <summary>
        /// Overridden method to get the item from a path.
        /// </summary>
        /// <param name="path">The drive path.</param>
        protected override void GetItem(string path)
        {
            if (GetDrive() == null)
            {
                return;
            }

            string relative_path = GetRelativePath(PSPathToNT(path));
            using (NtDirectory dir = GetPathDirectory(relative_path))
            {
                if (relative_path.Length == 0)
                {
                    WriteItemObject(new NtDirectoryEntry(GetDrive().DirectoryRoot, relative_path, String.Empty, "Directory"),
                            NTPathToPS(BuildDrivePath(relative_path)), true);
                }
                else
                {
                    ObjectDirectoryInformation dir_info = GetEntry(dir, relative_path);
                    if (dir_info != null)
                    {
                        WriteItemObject(new NtDirectoryEntry(GetDrive().DirectoryRoot, relative_path, dir_info.Name, dir_info.TypeName),
                            NTPathToPS(BuildDrivePath(relative_path)), dir_info.IsDirectory);
                    }
                }
            }
        }

        static Regex GlobToRegex(string glob, bool case_sensitive)
        {
            string escaped = Regex.Escape(glob);
            return new Regex("^" + escaped.Replace("\\*", ".*").Replace("\\?", ".") + "$", !case_sensitive ? RegexOptions.IgnoreCase : RegexOptions.None);
        }

        static bool HasGlobChars(string s)
        {
            return s.Contains('*') || s.Contains('?');
        }
         
        private void AddMatches(NtDirectory root, string base_path, IEnumerable<string> remaining, List<string> matches)
        {
            string current_entry = remaining.First();
            bool is_leaf = remaining.Count() == 1;
            List<ObjectDirectoryInformation> matching_entries = new List<ObjectDirectoryInformation>();
            
            if (root.IsAccessGranted(DirectoryAccessRights.Query))
            {
                // If this is not a leaf point we don't care about non-directory entries.
                ObjectDirectoryInformation[] dir_infos = root.Query().Where(d => is_leaf || d.IsDirectory).ToArray();
                foreach (ObjectDirectoryInformation dir_info in dir_infos)
                {
                    if (dir_info.Name.Equals(current_entry, StringComparison.OrdinalIgnoreCase))
                    {                        
                        matching_entries.Add(dir_info);
                        break;
                    }
                }

                // If we didn't find an explicit match then see if it's a glob.
                if (matching_entries.Count == 0 && HasGlobChars(current_entry))
                {
                    Regex globber = GlobToRegex(current_entry, false);
                    foreach (ObjectDirectoryInformation dir_info in dir_infos)
                    {
                        if (globber.IsMatch(dir_info.Name))
                        {
                            matching_entries.Add(dir_info);
                        }
                    }
                }
            }

            // Nothing matched.
            if (matching_entries.Count == 0)
            {
                return;
            }

            // We've reached the end of the road.
            if (is_leaf)
            {
                foreach (ObjectDirectoryInformation dir_info in matching_entries)
                {
                    string full_path = base_path + dir_info.Name;
                    _item_cache[full_path] = new NtDirectoryEntry(GetDrive().DirectoryRoot, PSPathToNT(full_path), dir_info.Name, dir_info.TypeName);
                    matches.Add(full_path);
                }
            }
            else
            {
                foreach (ObjectDirectoryInformation entry in matching_entries)
                {
                    try
                    {
                        using (NtDirectory dir = NtDirectory.Open(entry.Name, root, DirectoryAccessRights.Query))
                        {
                            AddMatches(dir, base_path + entry.Name + @"\", remaining.Skip(1), matches);
                        }
                    }
                    catch (NtException)
                    {
                    }
                }
            }
        }

        IEnumerable<string> ExpandDirectoryEntryMatches(string path)
        {
            Queue<string> remaining = new Queue<string>(path.Split('\\'));
            List<string> matches = new List<string>();

            if (remaining.Count == 0)
            {
                return matches;
            }

            try
            {
                string base_path = String.Join(@"\", remaining.Take(remaining.Count - 1));
                NtDirectory root_dir = GetDrive().DirectoryRoot;
                // We'll first try the general case of unglobbed dir and a globbed final name.
                using (NtDirectory base_dir = 
                    remaining.Count > 1 ? NtDirectory.Open(base_path, root_dir, DirectoryAccessRights.Query) 
                                        : root_dir.Duplicate(DirectoryAccessRights.Query))
                {
                    AddMatches(base_dir, BuildRelativePath(base_path, String.Empty), new string[] { remaining.Last() }, matches);
                }
            }
            catch (NtException)
            {
                // If we couldn't open the drive then try brute force approach.
                AddMatches(GetDrive().DirectoryRoot, String.Empty, remaining, matches);
            }

            return matches.Select(s => NTPathToPS(BuildDrivePath(s)));
        }

        /// <summary>
        /// Overidden method expand a wildcard in a path.
        /// </summary>
        /// <param name="path">The drive path with wildcards.</param>
        /// <returns>The list of expanded paths.</returns>
        protected override string[] ExpandPath(string path)
        {
            if (GetDrive() == null)
            {
                return new string[0];
            }
            
            return ExpandDirectoryEntryMatches(GetRelativePath(PSPathToNT(path))).ToArray();
        }

        /// <summary>
        /// Overridden method to create a new item.
        /// </summary>
        /// <param name="path">The drive path to create.</param>
        /// <param name="itemTypeName">The NT object type to create.</param>
        /// <param name="newItemValue">Additional item value data.</param>
        protected override void NewItem(string path, string itemTypeName, object newItemValue)
        {
            if (itemTypeName == null)
            {
                throw new ArgumentNullException("itemTypeName", "Must specify a typename");
            }

            NtObject obj = null;
            string relative_path = GetRelativePath(PSPathToNT(path));
            bool container = false;

            switch (itemTypeName.ToLower())
            {
                case "event":
                    obj = NtEvent.Create(relative_path, GetDrive().DirectoryRoot, EventType.NotificationEvent, false);
                    break;
                case "directory":
                    obj = NtDirectory.Create(relative_path, GetDrive().DirectoryRoot, DirectoryAccessRights.MaximumAllowed);
                    container = true;
                    break;
                case "symboliclink":
                case "link":
                    if (newItemValue == null)
                    {
                        throw new ArgumentNullException("newItemValue", "Must specify value for the symbolic link");
                    }
                    obj = NtSymbolicLink.Create(relative_path, GetDrive().DirectoryRoot, newItemValue.ToString());
                    break;
                case "mutant":
                    obj = NtMutant.Create(relative_path, GetDrive().DirectoryRoot, false);
                    break;
                case "semaphore":
                    int max_count = 1;
                    if (newItemValue != null)
                    {
                        max_count = Convert.ToInt32(newItemValue);
                    }
                    obj = NtSemaphore.Create(relative_path, GetDrive().DirectoryRoot, 0, max_count);
                    break;
                default:
                    throw new ArgumentException(String.Format("Can't create new object of type {0}", itemTypeName));
            }

            WriteItemObject(obj, path, container);
        }

        void ISecurityDescriptorCmdletProvider.GetSecurityDescriptor(string path, AccessControlSections includeSections)
        {
            string relative_path = GetRelativePath(PSPathToNT(path));
            using (NtDirectory dir = GetPathDirectory(relative_path))
            {
                if (relative_path.Length == 0)
                {
                    WriteItemObject(new GenericObjectSecurity(dir, includeSections), path, true);
                }
                else
                {
                    ObjectDirectoryInformation dir_info = GetEntry(dir, relative_path);
                    if (dir_info == null)
                    {
                        throw new NtException(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND);
                    }

                    using (NtObject obj = dir_info.Open(GenericAccessRights.ReadControl))
                    {
                        WriteItemObject(new GenericObjectSecurity(obj, includeSections), path, obj is NtDirectory);
                    }
                }
            }
        }


        void ISecurityDescriptorCmdletProvider.SetSecurityDescriptor(string path, ObjectSecurity securityDescriptor)
        {
            GenericObjectSecurity obj_security = securityDescriptor as GenericObjectSecurity;
            if (obj_security != null)
            {
                string relative_path = GetRelativePath(PSPathToNT(path));
                using (NtDirectory dir = GetPathDirectory(relative_path))
                {
                    ObjectDirectoryInformation dir_info = GetEntry(dir, relative_path);
                    if (dir_info == null)
                    {
                        throw new NtException(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND);
                    }

                    using (NtObject obj = dir_info.Open(GenericAccessRights.WriteDac))
                    {
                        obj_security.PersistHandle(obj.Handle);
                    }
                }
            }
        }

        ObjectSecurity ISecurityDescriptorCmdletProvider.NewSecurityDescriptorFromPath(string path, AccessControlSections includeSections)
        {
            return new GenericObjectSecurity();
        }

        ObjectSecurity ISecurityDescriptorCmdletProvider.NewSecurityDescriptorOfType(string type, AccessControlSections includeSections)
        {
            return new GenericObjectSecurity();
        }
    }
}
