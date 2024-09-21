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

using NtCoreLib;
using NtCoreLib.Kernel.ObjectManager;
using NtObjectManager.Utils;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Provider;
using System.Security.AccessControl;
using System.Text.RegularExpressions;

namespace NtObjectManager.Provider;

/// <summary>
/// Object manager provider.
/// </summary>
[CmdletProvider("NtObjectManager", ProviderCapabilities.ExpandWildcards)]
public sealed class NtObjectManagerProvider : NavigationCmdletProvider, ISecurityDescriptorCmdletProvider, IPropertyCmdletProvider
{
    private static readonly Dictionary<string, NtDirectoryEntry> _item_cache = new();

    private static string PSPathToNT(string path)
    {
        return path.Replace('\u2044', '/');
    }

    private static string NTPathToPS(string path)
    {
        return path.Replace('/', '\u2044');
    }

    private string GetDrivePath()
    {
        if (PSDriveInfo == null)
        {
            return string.Empty;
        }

        return PSDriveInfo.Root;
    }

    private const string GLOBAL_ROOT = @"nt:";
    private const string NAMESPACE_ROOT = @"ntpriv:";
    private const string KEY_ROOT = @"ntkey:";

    /// <summary>
    /// Overridden method to initialize default drives.
    /// </summary>
    /// <returns>The list of default drives.</returns>
    protected override Collection<PSDriveInfo> InitializeDefaultDrives()
    {
        Collection<PSDriveInfo> drives = new();
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            return drives;

        drives.Add(new PSDriveInfo("NtObject", ProviderInfo, GLOBAL_ROOT, "NT Object Manager Root Directory", null));
        int session_id = Process.GetCurrentProcess().SessionId;
        string base_dir;
        if (session_id == 0)
        {
            base_dir = GLOBAL_ROOT + "BaseNamedObjects";
        }
        else
        {
            base_dir = $@"{GLOBAL_ROOT}Sessions\{session_id}\BaseNamedObjects";
        }

        drives.Add(new PSDriveInfo("NtObjectSession", ProviderInfo,
            base_dir, "Current Session NT Objects", null));

        drives.Add(new PSDriveInfo("NtKey", ProviderInfo,
            KEY_ROOT, "Root NT Key Directory", null));

        string user_path = $@"User\{NtProcess.Current.User}";
        using (var key = NtKey.Open($@"\REGISTRY\{user_path}", null, KeyAccessRights.MaximumAllowed, KeyCreateOptions.NonVolatile, null, false))
        {
            if (key.IsSuccess)
            {
                drives.Add(new PSDriveInfo("NtKeyUser", ProviderInfo,
                    $@"{KEY_ROOT}{user_path}", "User NT Key Directory", null));
            }
            else
            {
                drives.Add(new PSDriveInfo("NtKeyUser", ProviderInfo,
                    $@"{KEY_ROOT}User\.DEFAULT", "User NT Key Directory", null));
            }
        }

        return drives;
    }

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
                       new ArgumentNullException(nameof(drive)),
                       "NullDrive",
                       ErrorCategory.InvalidArgument,
                       null));

            return null;
        }

        if (string.IsNullOrWhiteSpace(drive.Root) && (!drive.Root.StartsWith(GLOBAL_ROOT) 
            || !drive.Root.StartsWith(NAMESPACE_ROOT) 
            || !drive.Root.StartsWith(KEY_ROOT)))
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
                using var descriptor = BoundaryDescriptor.CreateFromString(drive.Root.Substring(NAMESPACE_ROOT.Length));
                using NtDirectory dir = NtDirectory.OpenPrivateNamespace(descriptor);
                ObjectManagerPSDriveInfo objmgr_drive = new(dir.Duplicate(), drive);
                return objmgr_drive;
            }
            else if (drive.Root.StartsWith(GLOBAL_ROOT))
            {
                using NtDirectory root = NtDirectory.Open(@"\");
                using NtDirectory dir = NtDirectory.Open(drive.Root.Substring(GLOBAL_ROOT.Length), root, DirectoryAccessRights.MaximumAllowed);
                ObjectManagerPSDriveInfo objmgr_drive = new(dir.Duplicate(), drive);
                return objmgr_drive;
            }
            else
            {
                using NtKey root = NtKey.Open(@"\Registry", null, KeyAccessRights.MaximumAllowed);
                using NtKey key = NtKey.Open(drive.Root.Substring(KEY_ROOT.Length).TrimStart('\\'), root, KeyAccessRights.MaximumAllowed);
                ObjectManagerPSDriveInfo objmgr_drive = new(key.Duplicate(), drive);
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
                       new ArgumentNullException(nameof(drive)),
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

        objmgr_drive.Close();

        return objmgr_drive;
    }

    /// <summary>
    /// Overridden method to check if path is valid.
    /// </summary>
    /// <param name="path">The path to check.</param>
    /// <returns>True if the path is valid.</returns>
    protected override bool IsValidPath(string path)
    {
        if (string.IsNullOrEmpty(path))
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
        return (ObjectManagerPSDriveInfo)PSDriveInfo;
    }

    private NtResult<NtObjectContainer> GetPathDirectory(string path, bool throw_on_error)
    {
        int last_slash = path.LastIndexOf('\\');
        if (last_slash == -1)
        {
            return GetDrive().DirectoryRoot.Duplicate(throw_on_error);
        }
        else
        {
            string base_path = path.Substring(0, last_slash);
            
            return GetDrive().DirectoryRoot.Open(base_path, throw_on_error);
        }
    }

    private NtResult<NtObjectContainer> GetDirectory(string path, bool throw_on_error)
    {
        if (path.Length == 0)
        {
            return GetDrive().DirectoryRoot.Duplicate(throw_on_error);
        }

        return GetDrive().DirectoryRoot.Open(path, throw_on_error);
    }

    private NtObjectContainerEntry GetEntry(NtObjectContainer dir, string path)
    {
        int last_slash = path.LastIndexOf('\\');
        if (last_slash != -1)
        {
            path = path.Substring(last_slash + 1);
        }

        return dir.GetEntry(path);
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

        using (var dir = GetPathDirectory(path, false))
        {
            if (dir.IsSuccess)
            {
                exists = GetEntry(dir.Result, path) != null;
            }
        }

        // If we can't find it indirectly, at least see if there's a directory with this name.
        return exists || GetDrive().DirectoryRoot.Exists(path);
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

        using (var dir = GetPathDirectory(path, false))
        {
            if (dir.IsSuccess)
            {
                var dir_info = GetEntry(dir.Result, path);
                is_container = dir_info?.IsDirectory ?? false;
            }
        }

        return is_container || GetDrive().DirectoryRoot.Exists(path);
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
            return $@"{drive_path}\{relative_path}";
        }
    }

    private static string BuildRelativePath(string relative_path, string name)
    {
        if (relative_path.Length == 0)
        {
            return name;
        }
        else
        {
            return $@"{relative_path}\{name}";
        }
    }

    private void GetChildItemsRecursive(string relative_path, bool recurse, uint depth)
    {
        try
        {
            using var dir = GetDirectory(relative_path, false);
            if (!dir.IsSuccess)
                return;

            Queue<string> dirs = new();
            foreach (var dir_info in dir.Result.Query())
            {
                string new_path = BuildRelativePath(relative_path, dir_info.Name);
                WriteItemObject(GetDrive().DirectoryRoot.CreateEntry(new_path, recurse ? new_path : dir_info.Name, dir_info.NtTypeName),
                    NTPathToPS(BuildDrivePath(new_path)), dir_info.IsDirectory);
                if (recurse && dir_info.IsDirectory)
                {
                    dirs.Enqueue(new_path);
                }
            }

            if (recurse && dirs.Count > 0 && depth > 0)
            {
                foreach (string new_dir in dirs)
                {
                    GetChildItemsRecursive(new_dir, recurse, depth != uint.MaxValue ? depth - 1 : uint.MaxValue);
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
    /// <param name="depth">Depth of the recursion.</param>
    protected override void GetChildItems(string path, bool recurse, uint depth)
    {
        if (GetDrive() == null)
        {
            return;
        }

        string relative_path = GetRelativePath(PSPathToNT(path));

        GetChildItemsRecursive(relative_path, recurse, depth);
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

        using var dir = GetDirectory(relative_path, false);
        if (!dir.IsSuccess)
            return;
        foreach (var dir_info in dir.Result.Query())
        {
            WriteItemObject(dir_info.Name, NTPathToPS(BuildDrivePath(BuildRelativePath(relative_path, dir_info.Name))), dir_info.IsDirectory);
        }
    }

    /// <summary>
    /// Overridden method to get the item from a path.
    /// </summary>
    /// <param name="path">The drive path.</param>
    protected override void GetItem(string path)
    {
        NtDirectoryEntry entry = GetItemFromPath(path);
        if (entry == null)
            return;
        WriteItemObject(entry, NTPathToPS(BuildDrivePath(GetRelativePath(PSPathToNT(path)))), entry.IsDirectory);
    }

    private void AddMatches(NtObjectContainer root, string base_path, IEnumerable<string> remaining, List<string> matches)
    {
        string current_entry = remaining.First();
        bool is_leaf = remaining.Count() == 1;
        List<NtObjectContainerEntry> matching_entries = new();
        
        if (root.QueryAccessGranted)
        {
            // If this is not a leaf point we don't care about non-directory entries.
            NtObjectContainerEntry[] dir_infos = root.Query().Where(d => is_leaf || d.IsDirectory).ToArray();
            foreach (var dir_info in dir_infos)
            {
                if (dir_info.Name.Equals(current_entry, StringComparison.OrdinalIgnoreCase))
                {
                    matching_entries.Add(dir_info);
                    break;
                }
            }

            // If we didn't find an explicit match then see if it's a glob.
            if (matching_entries.Count == 0 && PSUtils.HasGlobChars(current_entry))
            {
                Regex globber = PSUtils.GlobToRegex(current_entry, false);
                foreach (var dir_info in dir_infos)
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
            foreach (var dir_info in matching_entries)
            {
                string full_path = base_path + dir_info.Name;
                _item_cache[full_path] = GetDrive().DirectoryRoot.CreateEntry(PSPathToNT(full_path), dir_info.Name, dir_info.NtTypeName);
                matches.Add(full_path);
            }
        }
        else
        {
            foreach (var entry in matching_entries)
            {
                using var dir = root.OpenForQuery(entry.Name, false);
                if (!dir.IsSuccess)
                    continue;
                AddMatches(dir.Result, base_path + entry.Name + @"\", remaining.Skip(1), matches);
            }
        }
    }

    IEnumerable<string> ExpandDirectoryEntryMatches(string path)
    {
        Queue<string> remaining = new(path.Split('\\'));
        List<string> matches = new();

        if (remaining.Count == 0)
        {
            return matches;
        }

        try
        {
            string base_path = string.Join(@"\", remaining.Take(remaining.Count - 1));
            var root_dir = GetDrive().DirectoryRoot;
            // We'll first try the general case of unglobbed dir and a globbed final name.
            using var base_dir =
                remaining.Count > 1 ? root_dir.OpenForQuery(base_path, true).Result
                                    : root_dir.DuplicateForQuery(true).Result;
            AddMatches(base_dir, BuildRelativePath(base_path, string.Empty), new string[] { remaining.Last() }, matches);
        }
        catch (NtException)
        {
            // If we couldn't open the drive then try brute force approach.
            AddMatches(GetDrive().DirectoryRoot, string.Empty, remaining, matches);
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
            throw new ArgumentNullException(nameof(itemTypeName), "Must specify a typename");
        }

        NtObject obj = GetDrive().DirectoryRoot.NewItem(GetRelativePath(PSPathToNT(path)), itemTypeName, newItemValue);
        WriteItemObject(obj, path, obj.IsContainer);
    }

    void ISecurityDescriptorCmdletProvider.GetSecurityDescriptor(string path, AccessControlSections includeSections)
    {
        string relative_path = GetRelativePath(PSPathToNT(path));
        using var dir = GetPathDirectory(relative_path, true).Result;
        var sec = dir.GetSecurity(relative_path, includeSections);
        WriteItemObject(sec, path, sec.IsDirectory);
    }

    void ISecurityDescriptorCmdletProvider.SetSecurityDescriptor(string path, ObjectSecurity securityDescriptor)
    {
        if (securityDescriptor is GenericObjectSecurity obj_security)
        {
            string relative_path = GetRelativePath(PSPathToNT(path));
            using var dir = GetPathDirectory(relative_path, true).Result;
            dir.SetSecurity(relative_path, obj_security);
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

    void IPropertyCmdletProvider.GetProperty(string path, Collection<string> providerSpecificPickList)
    {
        NtDirectoryEntry entry = GetItemFromPath(path);
        if (entry == null)
            return;

        if (entry is NtKeyEntry key && key.ValueCount > 0)
        {
            var patterns = providerSpecificPickList.Select(s => new WildcardPattern(s, WildcardOptions.IgnoreCase)).ToArray();

            foreach (var val in key.Values)
            {
                if (patterns.Length == 0 || patterns.Any(p => p.IsMatch(val.Name)))
                    WritePropertyObject(val, path);
            }
        }
    }

    object IPropertyCmdletProvider.GetPropertyDynamicParameters(string path, Collection<string> providerSpecificPickList)
    {
        return null;
    }

    void IPropertyCmdletProvider.SetProperty(string path, PSObject propertyValue)
    {
        throw new NotImplementedException();
    }

    object IPropertyCmdletProvider.SetPropertyDynamicParameters(string path, PSObject propertyValue)
    {
        throw new NotImplementedException();
    }

    void IPropertyCmdletProvider.ClearProperty(string path, Collection<string> propertyToClear)
    {
        throw new NotImplementedException();
    }

    object IPropertyCmdletProvider.ClearPropertyDynamicParameters(string path, Collection<string> propertyToClear)
    {
        throw new NotImplementedException();
    }

    private NtDirectoryEntry GetItemFromPath(string path)
    {
        if (GetDrive() == null)
        {
            return null;
        }

        string relative_path = GetRelativePath(PSPathToNT(path));
        using var dir = GetPathDirectory(relative_path, false);
        if (!dir.IsSuccess)
            return null;
        if (relative_path.Length == 0)
        {
            return GetDrive().DirectoryRoot.CreateEntry(relative_path, string.Empty, "Directory");
        }
        else
        {
            var dir_info = GetEntry(dir.Result, relative_path);
            if (dir_info != null)
            {
                return GetDrive().DirectoryRoot.CreateEntry(relative_path, dir_info.Name, dir_info.NtTypeName);
            }
        }
        return null;
    }
}
