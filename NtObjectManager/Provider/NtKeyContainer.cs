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

internal class NtKeyContainer : NtObjectContainer
{
    private readonly NtKey _key;
    private readonly bool _open_for_backup;

    private NtResult<NtKey> Open(string path, KeyAccessRights desired_access, bool throw_on_error)
    {
        using var obja = new ObjectAttributes(path, AttributeFlags.OpenLink | AttributeFlags.CaseInsensitive, _key);
        return NtKey.Open(obja, desired_access, _open_for_backup ? KeyCreateOptions.BackupRestore : KeyCreateOptions.NonVolatile, throw_on_error);
    }

    public NtKeyContainer() 
        : this(NtKey.Open(@"\REGISTRY", null, KeyAccessRights.MaximumAllowed), false)
    {
    }

    public NtKeyContainer(NtKey key, bool open_for_backup) 
        : base(key)
    {
        _key = key;
        _open_for_backup = open_for_backup;
    }

    private NtObjectContainer Create(NtKey dir)
    {
        return new NtKeyContainer(dir, _open_for_backup);
    }

    public override bool QueryAccessGranted => _key.IsAccessGranted(KeyAccessRights.EnumerateSubKeys | KeyAccessRights.QueryValue);

    public override NtResult<NtObjectContainer> Duplicate(bool throw_on_error)
    {
        return _key.Duplicate(throw_on_error).Map(Create);
    }

    public override NtResult<NtObjectContainer> DuplicateForQuery(bool throw_on_error)
    {
        return _key.Duplicate(KeyAccessRights.EnumerateSubKeys | KeyAccessRights.QueryValue, throw_on_error).Map(Create);
    }

    public override NtDirectoryEntry CreateEntry(string relative_path, string name, string typename)
    {
        return new NtKeyEntry(_obj, relative_path, name, _open_for_backup);
    }

    public override bool Exists(string path)
    {
        if (path.Length == 0)
        {
            return true;
        }

        using var key = Open(path, KeyAccessRights.MaximumAllowed, false);
        return key.IsSuccess;
    }

    public override NtObjectContainerEntry GetEntry(string path)
    {
        if (path.Length == 0)
        {
            return new NtObjectContainerEntry(_key);
        }

        using var key = Open(path, KeyAccessRights.MaximumAllowed, false);
        if (!key.IsSuccess)
        {
            return null;
        }
        return new NtObjectContainerEntry(key.Result);
    }

    public override GenericObjectSecurity GetSecurity(string relative_path, AccessControlSections includeSections)
    {
        if (relative_path.Length == 0)
        {
            return new GenericObjectSecurity(_key, includeSections);
        }
        else
        {
            using var key = Open(relative_path, KeyAccessRights.ReadControl, false);
            if (!key.IsSuccess)
            {
                throw new NtException(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND);
            }

            return new GenericObjectSecurity(key.Result, includeSections);
        }
    }

    public override NtObject NewItem(string relative_path, string item_type_name, object new_item_value)
    {
        throw new NotImplementedException();
    }

    public override NtResult<NtObjectContainer> Open(string relative_path, bool throw_on_error)
    {
        if (relative_path.Length == 0)
        {
            return _key.Duplicate(throw_on_error).Map(Create);
        }

        return Open(relative_path, KeyAccessRights.MaximumAllowed, throw_on_error).Map(Create);
    }

    public override NtResult<NtObjectContainer> OpenForQuery(string relative_path, bool throw_on_error)
    {
        if (relative_path.Length == 0)
        {
            return _key.Duplicate(throw_on_error).Map(Create);
        }

        return Open(relative_path, KeyAccessRights.EnumerateSubKeys | KeyAccessRights.QueryValue,
                        throw_on_error).Map(Create);
    }

    public override IEnumerable<NtObjectContainerEntry> Query()
    {
        return _key.QueryKeys().Select(s => new NtObjectContainerEntry($@"{_key.FullPath}\{s}", s, "Key", true));
    }

    public override void SetSecurity(string relative_path, GenericObjectSecurity obj_security)
    {
        using var key = Open(relative_path, KeyAccessRights.WriteDac, false);
        if (!key.IsSuccess)
        {
            throw new NtException(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND);
        }
        obj_security.PersistHandle(key.Result.Handle);
    }
}
