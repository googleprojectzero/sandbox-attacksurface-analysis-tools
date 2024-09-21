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

using NtCoreLib.Utilities.Reflection;
using System;

namespace NtCoreLib.Win32.BindFilter;

/// <summary>
/// Flags for creating a bind link.
/// </summary>
[SDKName("CREATE_BIND_LINK_FLAGS"), Flags]
public enum CreateBindLinkFlags
{
    /// <summary>
    /// None
    /// </summary>
    [SDKName("CREATE_BIND_LINK_FLAG_NONE")]
    None = 0,
    /// <summary>
    /// Bind link is read only.
    /// </summary>
    [SDKName("CREATE_BIND_LINK_FLAG_READ_ONLY")]
    ReadOnly = 1,
    /// <summary>
    /// Bind link is merged.
    /// </summary>
    [SDKName("CREATE_BIND_LINK_FLAG_MERGED")]
    Merged = 2
};
