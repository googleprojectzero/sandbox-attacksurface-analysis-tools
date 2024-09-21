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
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtObjectManager.Provider;

/// <summary>
/// A class representing a NT key entry.
/// </summary>
public sealed class NtKeyEntry : NtDirectoryEntry
{
    private Dictionary<string, NtKeyValue> _value_dict;
    private KeyControlFlags _control_flags;
    private KeyVirtualizationFlags _virtualization_flags;
    private string _class_name;
    private readonly bool _open_for_backup;

    private protected override void PopulateKeyData(NtKey key)
    {
        base.PopulateKeyData(key);
        try
        {
            if (key.IsAccessGranted(KeyAccessRights.QueryValue))
            {
                _value_dict = key.QueryValues().ToDictionary(v => v.Name, StringComparer.OrdinalIgnoreCase);
            }
        }
        catch
        {
        }
        _class_name = key.ClassName;
        _control_flags = key.ControlFlags;
        _virtualization_flags = key.VirtualizationFlags;
    }

    private Dictionary<string, NtKeyValue> GetValueDict()
    {
        PopulateData();
        return _value_dict ?? new Dictionary<string, NtKeyValue>();
    }

    /// <summary>
    /// Try and open the directory entry and return an actual NtObject handle.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The object opened.</returns>
    /// <exception cref="System.ArgumentException">Thrown if invalid typename.</exception>
    public override NtResult<NtObject> ToObject(bool throw_on_error)
    {
        using var obja = new ObjectAttributes(RelativePath, AttributeFlags.OpenLink | AttributeFlags.CaseInsensitive, _root);
        return NtKey.Open(obja, KeyAccessRights.MaximumAllowed,
            _open_for_backup ? KeyCreateOptions.BackupRestore : KeyCreateOptions.NonVolatile,
            throw_on_error).Cast<NtObject>();
    }

    internal NtKeyEntry(NtObject root, string relative_path, string name, bool open_for_backup)
        : base(root, relative_path, name, "Key")
    {
        _open_for_backup = open_for_backup;
    }

    /// <summary>
    /// Get the key's values.
    /// </summary>
    public IEnumerable<NtKeyValue> Values => GetValueDict().Values;

    /// <summary>
    /// Get names of the values.
    /// </summary>
    public IEnumerable<string> ValueNames => Values.Select(v => v.Name);

    /// <summary>
    /// Get the number of values in the key.
    /// </summary>
    public int ValueCount => GetValueDict().Count;

    /// <summary>
    /// Get a key by name.
    /// </summary>
    /// <param name="name">The name of the key.</param>
    /// <returns>Returns the key if found or null.</returns>
    public NtKeyValue this[string name] => GetValueDict().TryGetValue(name, out NtKeyValue value) ? value : null;

    /// <summary>
    /// Get the default value for the key.
    /// </summary>
    public NtKeyValue DefaultValue => this[string.Empty];

    /// <summary>
    /// Get Key Control Flags.
    /// </summary>
    public KeyControlFlags ControlFlags
    {
        get
        {
            PopulateData();
            return _control_flags;
        }
    }

    /// <summary>
    /// Get key class name.
    /// </summary>
    public string ClassName
    {
        get
        {
            PopulateData();
            return _class_name;
        }
    }

    /// <summary>
    /// Get Key Virtualization Flags.
    /// </summary>
    public KeyVirtualizationFlags VirtualizationFlags
    {
        get
        {
            PopulateData();
            return _virtualization_flags;
        }
    }
}
