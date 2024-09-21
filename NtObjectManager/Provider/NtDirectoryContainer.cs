//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;

namespace NtObjectManager.Provider;

internal sealed class NtDirectoryContainer : NtObjectContainer
{
    private readonly NtDirectory _dir;
    private readonly NtKeyContainer _key;
    private readonly bool _root_dir;

    private const string REGISTRY_ROOT = @"REGISTRY";
    private const string REGISTRY_ROOT_DIR = @"REGISTRY\";

    public NtDirectoryContainer(NtDirectory dir) 
        : base(dir)
    {
        _dir = dir;
        if (dir.FullPath == @"\")
        {
            _root_dir = true;
            _key = new NtKeyContainer();
        }
    }

    private bool IsRegistryPath(string path)
    {
        if (_key != null)
        {
            return path.Equals(REGISTRY_ROOT, StringComparison.OrdinalIgnoreCase) || path.StartsWith(REGISTRY_ROOT_DIR, StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }

    private string GetRegistryPath(string path)
    {
        if (path.Equals(REGISTRY_ROOT, StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }
        return path.Substring(REGISTRY_ROOT_DIR.Length);
    }

    public override bool QueryAccessGranted => _dir.IsAccessGranted(DirectoryAccessRights.Query);

    private static NtObjectContainer Create(NtDirectory dir)
    {
        return new NtDirectoryContainer(dir);
    }

    public override NtResult<NtObjectContainer> Duplicate(bool throw_on_error)
    {
        return _dir.Duplicate(throw_on_error).Map(Create);
    }

    public override NtResult<NtObjectContainer> DuplicateForQuery(bool throw_on_error)
    {
        return _dir.Duplicate(DirectoryAccessRights.Query, throw_on_error).Map(Create);
    }

    public override bool Exists(string path)
    {
        if (IsRegistryPath(path))
        {
            return _key.Exists(GetRegistryPath(path));
        }

        if (_dir.FullPath == @"\" && path == "??")
            return true;

        return _dir.DirectoryExists(path);
    }

    public override NtObjectContainerEntry GetEntry(string path)
    {
        if (IsRegistryPath(path))
        {
            return _key.GetEntry(GetRegistryPath(path));
        }

        var dir_info = _dir.GetDirectoryEntry(path);
        if (dir_info == null)
        {
            return null;
        }
        return new NtObjectContainerEntry(dir_info);
    }

    public override GenericObjectSecurity GetSecurity(string relative_path, AccessControlSections includeSections)
    {
        if (relative_path.Length == 0)
        {
            return new GenericObjectSecurity(_dir, includeSections);
        }
        else
        {
            if (IsRegistryPath(relative_path))
            {
                return _key.GetSecurity(GetRegistryPath(relative_path), includeSections);
            }

            var dir_info = _dir.GetDirectoryEntry(relative_path);
            if (dir_info == null)
            {
                throw new NtException(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND);
            }

            using NtObject obj = dir_info.Open(GenericAccessRights.ReadControl);
            return new GenericObjectSecurity(obj, includeSections);
        }
    }

    public override NtObject NewItem(string relative_path, string item_type_name, object new_item_value)
    {
        switch (item_type_name.ToLower())
        {
            case "event":
                return NtEvent.Create(relative_path, _dir, EventType.NotificationEvent, false);
            case "directory":
                return NtDirectory.Create(relative_path, _dir, DirectoryAccessRights.MaximumAllowed);
            case "symboliclink":
            case "link":
                if (new_item_value == null)
                {
                    throw new ArgumentNullException(nameof(new_item_value), "Must specify value for the symbolic link");
                }
                return NtSymbolicLink.Create(relative_path, _dir, new_item_value.ToString());
            case "mutant":
                return NtMutant.Create(relative_path, _dir, false);
            case "semaphore":
                int max_count = 1;
                if (new_item_value != null)
                {
                    max_count = Convert.ToInt32(new_item_value);
                }
                return NtSemaphore.Create(relative_path, _dir, 0, max_count);
            default:
                throw new ArgumentException($"Can't create new object of type {item_type_name}");
        }
    }

    public override NtResult<NtObjectContainer> Open(string relative_path, bool throw_on_error)
    {
        if (IsRegistryPath(relative_path))
        {
            return _key.Open(GetRegistryPath(relative_path), throw_on_error);
        }

        if (_root_dir && relative_path == "??")
            relative_path = "GLOBAL??";

        return NtDirectory.Open(relative_path, _dir, 
            DirectoryAccessRights.MaximumAllowed, throw_on_error).Map(Create);
    }

    public override NtResult<NtObjectContainer> OpenForQuery(string relative_path, bool throw_on_error)
    {
        if (IsRegistryPath(relative_path))
        {
            return _key.OpenForQuery(GetRegistryPath(relative_path), throw_on_error);
        }

        if (_root_dir && relative_path == "??")
            relative_path = "GLOBAL??";

        return NtDirectory.Open(relative_path, _dir,
            DirectoryAccessRights.Query, throw_on_error).Map(Create);
    }

    public override IEnumerable<NtObjectContainerEntry> Query()
    {
        if (!QueryAccessGranted)
            return new NtObjectContainerEntry[0];
        return _dir.Query().Select(d => new NtObjectContainerEntry(d));
    }

    public override void SetSecurity(string relative_path, GenericObjectSecurity obj_security)
    {
        if (IsRegistryPath(relative_path))
        {
            _key.SetSecurity(GetRegistryPath(relative_path), obj_security);
            return;
        }

        var dir_info = _dir.GetDirectoryEntry(relative_path);
        if (dir_info == null)
        {
            throw new NtException(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND);
        }

        using NtObject obj = dir_info.Open(GenericAccessRights.WriteDac);
        obj_security.PersistHandle(obj.Handle);
    }

    public override void Dispose()
    {
        base.Dispose();
        _key?.Dispose();
    }
}
