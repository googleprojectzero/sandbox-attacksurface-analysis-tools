//  Copyright 2018 Google Inc. All Rights Reserved.
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

using NtCoreLib.Win32;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="description">Result object for setting a security descriptor.</para>
/// </summary>
public class Win32SetSecurityDescriptorResult
{
    /// <summary>
    /// The name of the resource which was set.
    /// </summary>
    public string Name { get; }
    /// <summary>
    /// The error during the operation.
    /// </summary>
    public Win32Error Error { get; }
    /// <summary>
    /// Whether security was set.
    /// </summary>
    public bool SecuritySet { get; }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="name">The name of the resource which was set.</param>
    /// <param name="error">The error during the operation.</param>
    /// <param name="security_set">Whether security was set.</param>
    internal Win32SetSecurityDescriptorResult(string name, Win32Error error, bool security_set)
    {
        Name = name;
        Error = error;
        SecuritySet = security_set;
    }
}
