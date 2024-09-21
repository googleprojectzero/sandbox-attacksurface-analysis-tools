//  Copyright 2021 Google Inc. All Rights Reserved.
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

using System;

namespace NtCoreLib.Image;

/// <summary>
/// Image resource type.
/// </summary>
public readonly struct ImageResourceType
{
    /// <summary>
    /// The name of the resource as a string.
    /// </summary>
    public ResourceString Name { get; }

    /// <summary>
    /// The well known type, is available (otherwise set to UNKNOWN)
    /// </summary>
    public WellKnownImageResourceType WellKnownType { get; }

    private static WellKnownImageResourceType GetWellKnownType(int type_id)
    {
        if (Enum.IsDefined(typeof(WellKnownImageResourceType), type_id))
        {
            return (WellKnownImageResourceType)type_id;
        }
        return WellKnownImageResourceType.Unknown;
    }

    internal ImageResourceType(IntPtr ptr)
    {
        Name = ResourceString.Create(ptr);
        WellKnownType = ImageUtils.GetWellKnownType(ptr);
    }

    internal ImageResourceType(ResourceString name)
    {
        Name = name;
        WellKnownType = name.Id.HasValue ? GetWellKnownType(name.Id.Value) : WellKnownImageResourceType.Unknown;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="name">The name of the type.</param>
    public ImageResourceType(string name)
    {
        if (ImageUtils.TryParseId(name, out int type_id))
        {
            Name = new ResourceString(type_id);
            WellKnownType = GetWellKnownType(type_id);
        }
        else
        {
            Name = new ResourceString(name);
            WellKnownType = WellKnownImageResourceType.Unknown;
        }
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="type_id">The name of the type.</param>
    public ImageResourceType(int type_id) 
        : this(new ResourceString(type_id))
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="type">The well known resource type.</param>
    public ImageResourceType(WellKnownImageResourceType type)
    {
        Name = new ResourceString((int)type);
        WellKnownType = type;
    }

    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The name of the type.</returns>
    public override string ToString()
    {
        return WellKnownType != WellKnownImageResourceType.Unknown ? WellKnownType.ToString() : $"\"{Name}\"";
    }
}
