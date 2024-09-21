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

#nullable enable

namespace NtCoreLib.Ndr.Ndr64;

/// <summary>
/// Class to represent a supplement type.
/// </summary>
[Serializable]
public sealed class Ndr64SupplementTypeReference : Ndr64BaseTypeReference
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public Ndr64FormatCharacter BaseType { get; }
    public Ndr64BaseTypeReference SupplementType { get; }

    // Supplementary arguments depend on the type. For bind context this is flags + context id.
    public int Argument1 { get; }
    public int Argument2 { get; }

    internal Ndr64SupplementTypeReference(Ndr64ParseContext context, IntPtr ptr)
        : base(Ndr64FormatCharacter.FC64_SUPPLEMENT)
    {
        BaseType = context.ReadFormat(ptr + 1);
        if (BaseType == Ndr64FormatCharacter.FC64_BIND_CONTEXT)
        {
            var context_handle = context.ReadStruct<NDR64_TYPE_STRICT_CONTEXT_HANDLE>(ptr);
            Argument1 = context_handle.CtxtFlags;
            Argument2 = context_handle.CtxtID;
            SupplementType = Read(context, context_handle.Type);
        }
        else
        {
            SupplementType = new Ndr64UnknownTypeReference(BaseType);
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}