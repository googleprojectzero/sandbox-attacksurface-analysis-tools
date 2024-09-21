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
/// Class for an NDR64 procedure handle parameter.
/// </summary>
[Serializable]
public class Ndr64ProcedureHandleParameter : Ndr64ProcedureParameter
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public Ndr64ContextHandleFlags Flags { get; }
    public bool Explicit { get; }
    public bool Generic { get; }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    internal Ndr64ProcedureHandleParameter(Ndr64ParamFlags attributes,
        Ndr64BaseTypeReference type, int offset, bool explicit_handle, Ndr64ContextHandleFlags flags, bool generic)
        : base(attributes, type, offset, "_hProcHandle")
    {
        Flags = flags;
        Explicit = explicit_handle;
        Generic = generic;
    }
}