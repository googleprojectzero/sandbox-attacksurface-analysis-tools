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
using NtCoreLib.Security.Authorization;
using System;

namespace NtObjectManager.Provider;

/// <summary>
/// A class representing a NT object manager directory entry.
/// </summary>
public class NtDirectoryEntry
{
    private protected readonly NtObject _root;
    private SecurityDescriptor _sd;
    private string _symlink_target;
    private bool? _is_symlink;
    private Enum _maximum_granted_access;
    private bool _data_populated;

    private protected virtual void PopulateKeyData(NtKey key)
    {
        _is_symlink = key.IsLink;
        _symlink_target = key.GetSymbolicLinkTarget(false).GetResultOrDefault(string.Empty);
    }

    private void PopulateDeviceData(NtFile file)
    {
        try
        {
            _device_type = file.DeviceType;
            _characteristics = file.Characteristics;
        }
        catch (NtException)
        {
        }
    }

    private protected void PopulateData()
    {
        if (!_data_populated)
        {
            _data_populated = true;
            _is_symlink = false;
            if (NtObject.CanOpenType(TypeName))
            {
                try
                {
                    using var result = ToObject(false);
                    if (!result.IsSuccess)
                    {
                        return;
                    }
                    var obj = result.Result;
                    if (obj.IsAccessMaskGranted(GenericAccessRights.ReadControl))
                    {
                        _sd = obj.GetSecurityDescriptor(SecurityInformation.AllBasic, false).GetResultOrDefault();
                    }

                    if (obj is NtSymbolicLink link)
                    {
                        _symlink_target = link.GetTarget(false).GetResultOrDefault(string.Empty);
                    }
                    else if (obj is NtKey key)
                    {
                        PopulateKeyData(key);
                    }
                    else if (obj is NtFile file)
                    {
                        PopulateDeviceData(file);
                    }

                    _maximum_granted_access = obj.GrantedAccessMask.ToSpecificAccess(obj.NtType.AccessRightsType);
                }
                catch
                {
                }
            }
        }
    }

    /// <summary>
    /// Get the name of the entry.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Get the NT type name of the entry.
    /// </summary>
    public string TypeName { get; }

    /// <summary>
    /// Indicates if this entry is a directory.
    /// </summary>
    public bool IsDirectory { get; }

    /// <summary>
    /// Indicates if this entry is a Device.
    /// </summary>
    public bool IsDevice { get; }

    /// <summary>
    /// Indicates if this entry is a symbolic link.
    /// </summary>
    public bool IsSymbolicLink
    {
        get
        {
            if (!_is_symlink.HasValue)
            {
                PopulateData();
            }
            return _is_symlink.Value;
        }
    }

    /// <summary>
    /// The relative path from the drive base to the entry.
    /// </summary>
    public string RelativePath { get; }

    /// <summary>
    /// The security descriptor of the entry. This can be null if caller does not have permission to open the actual object.
    /// </summary>
    public SecurityDescriptor SecurityDescriptor
    {
        get
        {
            PopulateData();
            return _sd;
        }
    }

    /// <summary>
    /// The symbolic link target if IsSymbolicLink is true. Can be null if caller doesn't have permission to open the actual object.
    /// </summary>
    public string SymbolicLinkTarget
    {
        get
        {
            PopulateData();
            return _symlink_target;
        }
    }

    /// <summary>
    /// The maximum granted access to the entry. Can be set to 0 if the caller doesn't have permission to open the actual object.
    /// </summary>
    public Enum MaximumGrantedAccess
    {
        get
        {
            PopulateData();
            return _maximum_granted_access;
        }
    }

    private FileDeviceType? _device_type;
    private FileDeviceCharacteristics? _characteristics;

    /// <summary>
    /// The device type.
    /// </summary>
    public FileDeviceType DeviceType
    {
        get
        {
            if (_device_type == null)
            {
                _device_type = FileDeviceType.UNKNOWN;
                PopulateData();
            }
            return _device_type.Value;
        }
    }

    /// <summary>
    /// The device characteristics.
    /// </summary>
    public FileDeviceCharacteristics Characteristics
    {
        get
        {
            if (_characteristics == null)
            {
                _characteristics = FileDeviceCharacteristics.None;
                PopulateData();
            }
            return _characteristics.Value;
        }
    }

    /// <summary>
    /// Try and open the directory entry and return an actual NtObject handle.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The object opened.</returns>
    /// <exception cref="System.ArgumentException">Thrown if invalid typename.</exception>
    public virtual NtResult<NtObject> ToObject(bool throw_on_error)
    {
        AttributeFlags flags = AttributeFlags.CaseInsensitive;
        if (TypeName.Equals("key", StringComparison.OrdinalIgnoreCase))
        {
            flags |= AttributeFlags.OpenLink;
        }

        if (_root.FullPath == @"\" && RelativePath.StartsWith(@"??\"))
        {
            return NtObject.OpenWithType(TypeName, @"\" + RelativePath, null,
                flags, GenericAccessRights.MaximumAllowed, null, throw_on_error);
        }

        return NtObject.OpenWithType(TypeName, RelativePath, _root,
            flags, GenericAccessRights.MaximumAllowed, null, throw_on_error);
    }

    /// <summary>
    /// Try and open the directory entry and return an actual NtObject handle.
    /// </summary>
    /// <returns>The object opened.</returns>
    /// <exception cref="NtException">Thrown if error opening object.</exception>
    /// <exception cref="System.ArgumentException">Thrown if invalid typename.</exception>
    public NtObject ToObject()
    {
        return ToObject(true).Result;
    }

    internal NtDirectoryEntry(NtObject root, string relative_path, string name, string typename)
    {
        Name = name;
        TypeName = typename;
        RelativePath = relative_path;
        _root = root;
        _is_symlink = false;

        switch (typename.ToLower())
        {
            case "directory":
                IsDirectory = true;
                break;
            case "key":
                IsDirectory = true;
                _is_symlink = null;
                break;
            case "symboliclink":
                _is_symlink = true;
                break;
            case "device":
                IsDevice = true;
                break;
        }

        _maximum_granted_access = GenericAccessRights.None;
        _sd = new SecurityDescriptor();
    }

    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The name of the directory entry.</returns>
    public override string ToString()
    {
        return Name;
    }
}
