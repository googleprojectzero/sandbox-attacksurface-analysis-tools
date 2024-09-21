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

/// <summary>
/// Class to represent the base of an array type.
/// </summary>
[Serializable]
public abstract class Ndr64BaseArrayTypeReference : Ndr64BaseTypeReference
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public int Alignment { get; private protected set; }
    public int ElementCount => GetElementCount();
    public int ElementSize => GetElementSize();

    protected abstract int GetElementCount();

    protected virtual int GetElementSize()
    {
        return GetSize() / GetElementCount();
    }

    private protected Ndr64BaseArrayTypeReference(Ndr64FormatCharacter format) : base(format)
    {
    }
}
