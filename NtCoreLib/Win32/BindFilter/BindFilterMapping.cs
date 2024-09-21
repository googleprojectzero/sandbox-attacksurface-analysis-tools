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

using System;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Win32.BindFilter;

/// <summary>
/// Class to represent a bind filter mapping.
/// </summary>
public sealed class BindFilterMapping
{
    /// <summary>
    /// The virtual root.
    /// </summary>
    public string VirtualRoot { get; }
    /// <summary>
    /// The flags it was registered with.
    /// </summary>
    public BfSetupFilterFlags Flags { get; }
    /// <summary>
    /// List of target roots.
    /// </summary>
    public IReadOnlyList<string> TargetRoots { get; }

    internal BindFilterMapping(string virtual_root, BfSetupFilterFlags flags, IEnumerable<string> target_roots)
    {
        VirtualRoot = virtual_root ?? throw new ArgumentNullException(nameof(virtual_root));
        Flags = flags;
        TargetRoots = target_roots?.ToList().AsReadOnly() ?? throw new ArgumentNullException(nameof(target_roots));
    }
}