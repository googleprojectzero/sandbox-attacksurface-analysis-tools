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
/// Attribute to indicate the required version for a function.
/// Applied if the function needs a version greater than 7.
/// </summary>
public sealed class SupportedVersionAttribute : Attribute
{
    /// <summary>
    /// The supported version.
    /// </summary>
    public SupportedVersion Version { get; }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="version">The supported version</param>
    public SupportedVersionAttribute(SupportedVersion version)
    {
        Version = version;
    }
}
