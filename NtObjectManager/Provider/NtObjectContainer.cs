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
using NtCoreLib.Security.Authorization;
using System;
using System.Collections.Generic;
using System.Security.AccessControl;

namespace NtObjectManager.Provider;

internal abstract class NtObjectContainer : IDisposable
{
    private protected readonly NtObject _obj;

    private protected NtObjectContainer(NtObject obj)
    {
        _obj = obj;
    }

    public string FullPath => _obj.FullPath;

    public SecurityDescriptor SecurityDescriptor => _obj.SecurityDescriptor;

    public abstract bool Exists(string path);

    public abstract NtResult<NtObjectContainer> Duplicate(bool throw_on_error);

    public abstract NtResult<NtObjectContainer> DuplicateForQuery(bool throw_on_error);

    public abstract NtResult<NtObjectContainer> Open(string relative_path, bool throw_on_error);

    public abstract NtResult<NtObjectContainer> OpenForQuery(string relative_path, bool throw_on_error);

    public abstract bool QueryAccessGranted { get; }

    public abstract IEnumerable<NtObjectContainerEntry> Query();

    public abstract NtObjectContainerEntry GetEntry(string path);

    public virtual NtDirectoryEntry CreateEntry(string relative_path, string name, string typename)
    {
        return new NtDirectoryEntry(_obj, relative_path, name, typename);
    }

    public abstract GenericObjectSecurity GetSecurity(string relative_path, AccessControlSections includeSections);

    public abstract void SetSecurity(string relative_path, GenericObjectSecurity obj_security);

    public abstract NtObject NewItem(string relative_path, string item_type_name, object new_item_value);

    public virtual void Dispose()
    {
        _obj?.Dispose();
    }
}
