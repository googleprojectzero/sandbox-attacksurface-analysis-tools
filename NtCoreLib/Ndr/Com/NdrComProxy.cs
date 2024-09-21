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

// NOTE: This file is a modified version of COMProxyInstance.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using System.Collections.Generic;
using System.Linq;
using NtCoreLib.Ndr.Dce;

namespace NtCoreLib.Ndr.Com;

/// <summary>
/// Class to represent a parsed COM proxy.
/// </summary>
public sealed class NdrComProxy
{
    /// <summary>
    /// The list of interface proxies.
    /// </summary>
    public IReadOnlyList<NdrComProxyInterface> Interfaces { get; }

    /// <summary>
    /// List of parsed types.
    /// </summary>
    public IReadOnlyList<NdrBaseTypeReference> Types { get; }

    /// <summary>
    /// List of complex types.
    /// </summary>
    public IReadOnlyList<NdrComplexTypeReference> ComplexTypes { get; }

    internal NdrComProxy(IEnumerable<NdrComProxyInterface> interfaces, NdrTypeCache type_cache)
    {
        Interfaces = interfaces.ToList().AsReadOnly();
        Types = type_cache.Types.ToList().AsReadOnly();
        ComplexTypes = type_cache.ComplexTypes.ToList().AsReadOnly();
    }
}
