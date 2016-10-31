//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
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
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Provider;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Diagnostics;

namespace SandboxPowerShellApi
{
    [CmdletProvider("ObjectManager", ProviderCapabilities.ExpandWildcards)]
    public class ObjectManagerProvider : NavigationCmdletProvider, ISecurityDescriptorCmdletProvider
    {
        private static Dictionary<string, ObjectDirectoryEntry> _item_cache = new Dictionary<string, ObjectDirectoryEntry>();

        private class ObjectManagerPSDriveInfo : PSDriveInfo
        {
            public ObjectManagerPSDriveInfo(NtDirectory root, PSDriveInfo drive_info) 
                : base(drive_info)
            {
                DirectoryRoot = root;
            }            

            public NtDirectory DirectoryRoot { get; private set; }
        }

        private static string NormalizePath(string path)
        {
            string ret = path.Replace('\u2044', '/').Trim('\\');
            return ret;
        }

        private static string DenomalizePath(string path)
        {
            return path.Replace('/', '\u2044');
        }

        protected override Collection<PSDriveInfo> InitializeDefaultDrives()
        {
            PSDriveInfo drive = new PSDriveInfo("Objects", this.ProviderInfo, @"\", "Object Manager Root Directory", null);
            PSDriveInfo session = new PSDriveInfo("SessionObjects", this.ProviderInfo, 
                String.Format(@"\Sessions\{0}\BaseNamedObjects", Process.GetCurrentProcess().SessionId), "Current Session Objects", null);
            Collection<PSDriveInfo> drives = new Collection<PSDriveInfo>() { drive, session };
            return drives;
        }

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

            if (String.IsNullOrWhiteSpace(drive.Root))
            {
                WriteError(new ErrorRecord(
                           new ArgumentException("drive.Root"),
                           "NoRoot",
                           ErrorCategory.InvalidArgument,
                           drive));

                return null;
            }

            try
            {
                using (NtDirectory dir = NtDirectory.Open(drive.Root))
                {
                    ObjectManagerPSDriveInfo objmgr_drive = new ObjectManagerPSDriveInfo(dir.Duplicate(), drive);
                    return objmgr_drive;
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

        protected override bool IsValidPath(string path)
        {
            if (String.IsNullOrEmpty(path))
            {
                return false;
            }

            path = NormalizePath(path);
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

        private ObjectManagerPSDriveInfo GetDrive()
        {
            return (ObjectManagerPSDriveInfo)this.PSDriveInfo;
        }
        private NtDirectory GetPathDirectory(string path)
        {
            path = NormalizePath(path);
            int last_slash = path.LastIndexOf('\\');
            if (last_slash == -1)
            {
                return GetDrive().DirectoryRoot.Duplicate();
            }
            else
            {
                NtDirectory dir = GetDrive().DirectoryRoot;
                string base_path = path.Substring(0, last_slash);
                //if (IsGlobalRoot(base_path))
                //{
                //    base_path = @"\";
                //    dir = null;
                //}
                
                return NtDirectory.Open(base_path,
                        dir, DirectoryAccessRights.MaximumAllowed);
            }
        }

        //private bool IsGlobalRoot(string path)
        //{
        //    try
        //    {
        //        using (NtSymbolicLink link = NtSymbolicLink.Open(path, GetDrive().DirectoryRoot, SymbolicLinkAccessRights.Query))
        //        {
        //            if (String.IsNullOrEmpty(link.Query()))
        //            {
        //                return true;
        //            }
        //        }
        //    }
        //    catch (NtException)
        //    {
        //    }

        //    return false;
        //}

        private NtDirectory GetDirectory(string path)
        {
            path = NormalizePath(path);
            if (path.Length == 0)
            {
                return GetDrive().DirectoryRoot.Duplicate();
            }

            NtDirectory dir = GetDrive().DirectoryRoot;
            //if (IsGlobalRoot(path))
            //{
            //    path = @"\";
            //    dir = null;
            //}

            return NtDirectory.Open(path,
                dir, DirectoryAccessRights.MaximumAllowed);
        }

        private ObjectDirectoryInformation GetEntry(NtDirectory dir, string path)
        {
            path = NormalizePath(path);
            int last_slash = path.LastIndexOf('\\');
            if (last_slash != -1)
            {
                path = path.Substring(last_slash + 1);
            }

            return dir.GetDirectoryEntry(path);
        }
        
        protected override bool ItemExists(string path)
        {
            bool exists = false;

            if (GetDrive() == null)
            {
                return false;
            }

            path = NormalizePath(path);
            // The root always exists.
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

        protected override bool IsItemContainer(string path)
        {
            bool is_container = false;
            bool is_symlink = false;

            if (GetDrive() == null)
            {
                return false;
            }

            path = NormalizePath(path);
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
                    is_symlink = dir_info != null
                        && dir_info.TypeName.Equals("symboliclink", StringComparison.OrdinalIgnoreCase);
                }
            }
            catch (NtException)
            {   
            }

            //if (is_symlink && IsGlobalRoot(path))
            //{
            //    is_container = true;
            //}

            return is_container || GetDrive().DirectoryRoot.DirectoryExists(path); 
        }

        protected override void GetChildItems(string path, bool recurse)
        {
            if (GetDrive() == null)
            {
                return;
            }

            using (NtDirectory dir = GetDirectory(path))
            {
                foreach (ObjectDirectoryInformation dir_info in dir.Query())
                {
                    WriteItemObject(new ObjectDirectoryEntry(GetDrive().DirectoryRoot, NormalizePath(String.Format(@"{0}\{1}", path, dir_info.Name)), dir_info.Name, dir_info.TypeName), path, dir_info.IsDirectory);
                }
            }
        }

        protected override void GetChildNames(string path, ReturnContainers returnContainers)
        {
            if (GetDrive() == null)
            {
                return;
            }

            using (NtDirectory dir = GetDirectory(path))
            {
                foreach (ObjectDirectoryInformation dir_info in dir.Query())
                {
                    WriteItemObject(dir_info.Name, path, dir_info.IsDirectory);
                }
            }
        }

        protected override void GetItem(string path)
        {
            if (GetDrive() == null)
            {
                return;
            }

            string normalized_path = NormalizePath(path);
            if (_item_cache.ContainsKey(normalized_path))
            {
                ObjectDirectoryEntry entry = _item_cache[normalized_path];
                WriteItemObject(entry, path, entry.IsDirectory);
            }
            else
            {
                using (NtDirectory dir = GetPathDirectory(path))
                {
                    ObjectDirectoryInformation dir_info = GetEntry(dir, path);
                    if (dir_info != null)
                    {
                        WriteItemObject(new ObjectDirectoryEntry(GetDrive().DirectoryRoot, normalized_path, dir_info.Name, dir_info.TypeName), path.TrimStart('\\'), dir_info.IsDirectory);
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
                    _item_cache[full_path] = new ObjectDirectoryEntry(GetDrive().DirectoryRoot, NormalizePath(full_path), dir_info.Name, dir_info.TypeName);
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
            Queue<string> remaining = new Queue<string>(NormalizePath(path).Split('\\'));
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
                    AddMatches(base_dir, base_path + @"\", new string[] { remaining.Last() }, matches);
                }
            }
            catch (NtException)
            {
                // If we couldn't open the drive then try brute force approach.
                AddMatches(GetDrive().DirectoryRoot, @"", remaining, matches);
            }

            return matches.Select(s => DenomalizePath(s));
        }

        protected override string[] ExpandPath(string path)
        {
            if (GetDrive() == null)
            {
                return new string[0];
            }
            
            return ExpandDirectoryEntryMatches(path).ToArray();
        }

        public void GetSecurityDescriptor(string path, AccessControlSections includeSections)
        {
            using (NtDirectory dir = GetPathDirectory(path))
            {
                ObjectDirectoryInformation dir_info = GetEntry(dir, path);
                if (dir_info == null)
                {
                    throw new NtException(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND);
                }

                using (NtObject obj = dir_info.Open(GenericAccessRights.ReadControl))
                {
                    WriteItemObject(new GenericObjectSecurity(obj, includeSections), path, false);
                }
            }
        }

        protected override void NewItem(string path, string itemTypeName, object newItemValue)
        {
            if (itemTypeName == null)
            {
                throw new ArgumentNullException("itemTypeName", "Must specify a typename");
            }

            NtObject obj = null;
            string normalized_path = NormalizePath(path);
            bool container = false;

            switch (itemTypeName.ToLower())
            {
                case "event":
                    obj = NtEvent.Create(normalized_path, GetDrive().DirectoryRoot, EventType.NotificationEvent, false);
                    break;
                case "directory":
                    obj = NtDirectory.Create(normalized_path, GetDrive().DirectoryRoot, DirectoryAccessRights.MaximumAllowed);
                    container = true;
                    break;
                case "symboliclink":
                case "link":
                    if (newItemValue == null)
                    {
                        throw new ArgumentNullException("newItemValue", "Must specify value for the symbolic link");
                    }
                    obj = NtSymbolicLink.Create(normalized_path, GetDrive().DirectoryRoot, newItemValue.ToString());
                    break;
                case "mutant":
                    obj = NtMutant.Create(normalized_path, GetDrive().DirectoryRoot, false);
                    break;
                case "semaphore":
                    int max_count = 1;
                    if (newItemValue != null)
                    {
                        max_count = Convert.ToInt32(newItemValue);
                    }
                    obj = NtSemaphore.Create(normalized_path, GetDrive().DirectoryRoot, 0, max_count);
                    break;
                default:
                    throw new ArgumentException(String.Format("Can't create new object of type {0}", itemTypeName));
            }

            WriteItemObject(obj, path, container);
        }

        public void SetSecurityDescriptor(string path, ObjectSecurity securityDescriptor)
        {
            GenericObjectSecurity obj_security = securityDescriptor as GenericObjectSecurity;
            if (obj_security != null)
            {
                using (NtDirectory dir = GetPathDirectory(path))
                {
                    ObjectDirectoryInformation dir_info = GetEntry(dir, path);
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

        public ObjectSecurity NewSecurityDescriptorFromPath(string path, AccessControlSections includeSections)
        {
            return new GenericObjectSecurity();
        }

        public ObjectSecurity NewSecurityDescriptorOfType(string type, AccessControlSections includeSections)
        {
            return new GenericObjectSecurity();
        }
    }
}
