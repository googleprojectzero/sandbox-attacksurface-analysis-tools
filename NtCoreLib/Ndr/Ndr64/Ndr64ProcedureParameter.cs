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
/// Class for an NDR64 procedure parameter.
/// </summary>
[Serializable]
public class Ndr64ProcedureParameter
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public Ndr64ParamFlags Attributes { get; }
    public Ndr64BaseTypeReference Type { get; }
    public int StackOffset { get; }
    public string Name { get; set; }
    public bool IsIn => Attributes.HasFlag(Ndr64ParamFlags.IsIn);
    public bool IsOut => Attributes.HasFlag(Ndr64ParamFlags.IsOut);
    public bool IsInOut => IsIn && IsOut;
    public bool IsSimpleRef => Attributes.HasFlag(Ndr64ParamFlags.IsSimpleRef);
    public bool IsPipe => Attributes.HasFlag(Ndr64ParamFlags.IsPipe);

    public override string ToString() => $"{Type} - {Attributes}";
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member

    internal Ndr64ProcedureParameter(Ndr64ParseContext context, NDR64_PARAM_FORMAT param_format, string name) 
        : this(param_format.Attributes, Ndr64BaseTypeReference.Read(context, param_format.Type), 
              param_format.StackOffset, name)
    {
    }

    internal Ndr64ProcedureParameter(Ndr64ParamFlags attributes, Ndr64BaseTypeReference type, int stack_offset, string name)
    {
        Attributes = attributes;
        Type = type;
        StackOffset = stack_offset;
        Name = name;
    }
}
