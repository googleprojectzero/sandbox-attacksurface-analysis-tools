//  Copyright 2023 Google LLC. All Rights Reserved.
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

namespace NtCoreLib.Ndr.Ndr64;
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public sealed class Ndr64IndirectTypeReference : Ndr64BaseTypeReference
{
    public Ndr64BaseTypeReference RefType { get; private set; }

    internal void FixupType(Ndr64BaseTypeReference ref_type)
    {
        RefType = ref_type;
    }

    internal Ndr64IndirectTypeReference() : base(Ndr64FormatCharacter.FC64_ZERO)
    {
    }

    //public override int GetSize()
    //{
    //    return RefType.GetSize();
    //}

    public override string ToString()
    {
        return RefType.ToString();
    }
}
#pragma warning restore 1591