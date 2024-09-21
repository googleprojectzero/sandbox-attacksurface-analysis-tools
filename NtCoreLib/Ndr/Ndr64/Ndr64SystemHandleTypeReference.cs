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

using NtCoreLib.Security.Authorization;
using System;

namespace NtCoreLib.Ndr.Ndr64;

/// <summary>
/// Class to represent a NDR64 system handle.
/// </summary>
[Serializable]
public sealed class Ndr64SystemHandleTypeReference : Ndr64BaseTypeReference
{
    // IDL is [system_handle(sh_file, 0x1234)]HANDLE

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public Ndr64SystemHandleType HandleType { get; }
    public AccessMask DesiredAccesss { get; }

    internal Ndr64SystemHandleTypeReference(Ndr64ParseContext context, IntPtr ptr)
        : base(Ndr64FormatCharacter.FC64_SYSTEM_HANDLE)
    {
        var sys_handle = context.ReadStruct<NDR64_SYSTEM_HANDLE_FORMAT>(ptr);
        HandleType = (Ndr64SystemHandleType)sys_handle.HandleType;
        DesiredAccesss = sys_handle.DesiredAccess;
    }

    public override int GetSize()
    {
        return IntPtr.Size;
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}