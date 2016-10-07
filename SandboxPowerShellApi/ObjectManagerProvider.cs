using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Provider;
using System.Text.RegularExpressions;
using System.Security.AccessControl;

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
            return path.Replace('\u2044', '/').Trim('\\');
        }

        private static string DenomalizePath(string path)
        {
            return path.Replace('/', '\u2044');
        }

        protected override Collection<PSDriveInfo> InitializeDefaultDrives()
        {
            PSDriveInfo drive = new PSDriveInfo("Objects", this.ProviderInfo, "\\", "Object Manager Root Directory", null);
            Collection<PSDriveInfo> drives = new Collection<PSDriveInfo>() { drive };
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

            if (String.IsNullOrEmpty(drive.Root))
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
                string path = NormalizePath(drive.Root);
                if (path.Length == 0)
                {
                    path = "\\";
                }
                using (NtDirectory dir = NtDirectory.Open(path))
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
                return NtDirectory.Open(path.Substring(0, last_slash), 
                    GetDrive().DirectoryRoot, DirectoryAccessRights.MaximumAllowed);
            }
        }

        private NtDirectory GetDirectory(string path)
        {
            path = NormalizePath(path);
            if (path.Length == 0)
            {
                return GetDrive().DirectoryRoot.Duplicate();
            }
            else
            {
                return NtDirectory.Open(path,
                    GetDrive().DirectoryRoot, DirectoryAccessRights.MaximumAllowed);
            }
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
            try
            {
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

                using (NtDirectory dir = GetPathDirectory(path))
                {
                    return GetEntry(dir, path) != null;
                }
            }
            catch (NtException)
            {
            }

            return false;
        }

        protected override bool IsItemContainer(string path)
        {
            if (GetDrive() == null)
            {
                return false;
            }

            path = NormalizePath(path);
            if (path.Length == 0)
            {
                return true;
            }

            return GetDrive().DirectoryRoot.DirectoryExists(NormalizePath(path));
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
                    WriteItemObject(new ObjectDirectoryEntry(GetDrive().DirectoryRoot, NormalizePath(path), dir_info), path, dir_info.IsDirectory);
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
                        WriteItemObject(new ObjectDirectoryEntry(GetDrive().DirectoryRoot, normalized_path, dir_info), path, dir_info.IsDirectory);
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
                    _item_cache[full_path] = new ObjectDirectoryEntry(GetDrive().DirectoryRoot, NormalizePath(full_path), dir_info);
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
            if (remaining.Count > 0)
            {
                AddMatches(GetDrive().DirectoryRoot, @"\", remaining, matches);
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
            string normalized_path = NormalizePath(path);
            SecurityDescriptor sd = null;
            if (_item_cache.ContainsKey(normalized_path))
            {
                ObjectDirectoryEntry entry = _item_cache[normalized_path];
                sd = entry.SecurityDescriptor;
            }
            else
            {
                using (NtDirectory dir = GetPathDirectory(path))
                {
                    ObjectDirectoryInformation dir_info = GetEntry(dir, path);
                    ObjectDirectoryEntry entry = new ObjectDirectoryEntry(GetDrive().DirectoryRoot, NormalizePath(path), dir_info);
                    sd = entry.SecurityDescriptor;
                }
            }
            WriteItemObject(sd, path, false);
        }

        public void SetSecurityDescriptor(string path, ObjectSecurity securityDescriptor)
        {
            throw new NotImplementedException();
        }

        public ObjectSecurity NewSecurityDescriptorFromPath(string path, AccessControlSections includeSections)
        {
            throw new NotImplementedException();
        }

        public ObjectSecurity NewSecurityDescriptorOfType(string type, AccessControlSections includeSections)
        {
            throw new NotImplementedException();
        }
    }
}
