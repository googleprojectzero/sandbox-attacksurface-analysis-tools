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

// NOTE: This file is a modified version of NdrParser.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using System;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Ndr.Dce;

[Serializable]
internal class NdrTypeCache
{
    private int _complex_id;

    public Dictionary<IntPtr, NdrBaseTypeReference> Cache { get; } = new();

    public int GetNextComplexId()
    {
        return _complex_id++;
    }

    internal void FixupLateBoundTypes()
    {
        foreach (var type in Cache.Values)
        {
            type.FixupLateBoundTypes();
        }
    }

    public IEnumerable<NdrBaseTypeReference> Types
    {
        get
        {
            FixupLateBoundTypes();
            return Cache.Values;
        }
    }

    public IEnumerable<NdrComplexTypeReference> ComplexTypes => Types.OfType<NdrComplexTypeReference>();
}