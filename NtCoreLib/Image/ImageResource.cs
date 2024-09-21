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
/// Class to represent a resource in an image.
/// </summary>
public readonly struct ImageResource
{
    private readonly byte[] _data;

    /// <summary>
    /// The name of the resource.
    /// </summary>
    public ResourceString Name { get; }

    /// <summary>
    /// The type of the resource.
    /// </summary>
    public ImageResourceType Type { get; }

    /// <summary>
    /// The size of the resource.
    /// </summary>
    public int Size => _data?.Length ?? 0;

    /// <summary>
    /// Get the associated language.
    /// </summary>
    internal int Language { get; }

    /// <summary>
    /// Get the resource as a byte array.
    /// </summary>
    /// <returns>The resource as a byte array.</returns>
    public byte[] ToArray()
    {
        return _data?.CloneBytes() ?? throw new InvalidOperationException("Resource data wasn't loaded.");
    }

    internal ImageResource(ResourceString name, ImageResourceType type, byte[] data, int language = 0)
    {
        Name = name;
        Type = type;
        _data = data;
        Language = language;
    }
}
