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

using System;

namespace NtCoreLib.Utilities.Reflection;

/// <summary>
/// Attribute to apply to a enum or a structure to indicate the original SDK name.
/// </summary>
/// <remarks>This is only used when formatting the value.</remarks>
[AttributeUsage(AttributeTargets.All, AllowMultiple = false)]
public sealed class SDKNameAttribute : Attribute
{
    /// <summary>
    /// The SDK name associated with this meta-data.
    /// </summary>
    public string Name { get; }
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="name">The SDK name associated with this meta-data.</param>
    public SDKNameAttribute(string name)
    {
        Name = name;
    }
}
