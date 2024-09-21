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

using NtCoreLib.Ndr.Parser;
using NtCoreLib.Win32.Debugger.Symbols;
using System;
using System.Collections.Generic;
using RTMarshal = System.Runtime.InteropServices.Marshal;

namespace NtCoreLib.Ndr.Ndr64;

/// <summary>
/// Class for an NDR64 procedure definition.
/// </summary>
[Serializable]
public sealed class Ndr64ProcedureDefinition
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public string Name { get; set; }
    public IReadOnlyList<Ndr64ProcedureParameter> Params { get; }
    public Ndr64ProcedureParameter ReturnValue { get; }
    public Ndr64ProcedureHandleParameter Handle { get; }
    public uint RpcFlags { get; }
    public int ProcNum { get; }
    public int StackSize { get; }
    public bool HasAsyncHandle { get; }
    public IntPtr DispatchFunction { get; }
    public int DispatchOffset { get; }
    public int ConstantClientBufferSize { get; }
    public int ConstantServerBufferSize { get; }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member

    internal Ndr64ProcedureDefinition(Ndr64ParseContext context, IntPtr format_info, 
        ISymbolResolver symbol_resolver, IntPtr dispatch_func,
        IntPtr base_offset, string name, int proc_num, NdrParserFlags parser_flags)
    {
        var proc_format = context.ReadStruct<NDR64_PROC_FORMAT>(format_info);
        ProcNum = proc_num;

        if (string.IsNullOrWhiteSpace(name))
        {
            if (symbol_resolver != null && dispatch_func != IntPtr.Zero)
            {
                Name = symbol_resolver.GetSymbolForAddress(dispatch_func, false, true);
            }

            Name ??= $"Proc{ProcNum}";
        }
        else
        {
            Name = name;
        }

        StackSize = proc_format.StackSize;
        ConstantClientBufferSize = proc_format.ConstantClientBufferSize;
        ConstantServerBufferSize = proc_format.ConstantServerBufferSize;

        if (proc_format.Flags.HandleType == NDR64_HANDLE_TYPE.NDR64_FC_EXPLICIT_HANDLE
            && proc_format.ExtensionSize == RTMarshal.SizeOf<NDR64_BIND_AND_NOTIFY_EXTENSION>())
        {
            var handle = context.ReadStruct<NDR64_BIND_AND_NOTIFY_EXTENSION>(format_info + RTMarshal.SizeOf<NDR64_PROC_FORMAT>());
            Ndr64BaseTypeReference handle_type = new Ndr64HandleTypeReference(handle.Binding.HandleType);
            if (handle.Binding.Flags.HasFlagSet(Ndr64ContextHandleFlags.IsViaPointer))
            {
                handle_type = new Ndr64PointerTypeReference(handle_type);
            }
            Handle = new Ndr64ProcedureHandleParameter(0, handle_type, handle.Binding.StackOffset,
                true, handle.Binding.Flags, handle.Binding.HandleType == Ndr64FormatCharacter.FC64_BIND_GENERIC);
        }
        else
        {
            var handle_type = proc_format.Flags.HandleType switch
            {
                NDR64_HANDLE_TYPE.NDR64_FC_AUTO_HANDLE => Ndr64FormatCharacter.FC64_AUTO_HANDLE,
                NDR64_HANDLE_TYPE.NDR64_FC_BIND_GENERIC => Ndr64FormatCharacter.FC64_BIND_GENERIC,
                NDR64_HANDLE_TYPE.NDR64_FC_BIND_PRIMITIVE => Ndr64FormatCharacter.FC64_BIND_PRIMITIVE,
                NDR64_HANDLE_TYPE.NDR64_FC_CALLBACK_HANDLE => Ndr64FormatCharacter.FC64_CALLBACK_HANDLE,
                _ => Ndr64FormatCharacter.FC64_IGNORE,
            };
            Handle = new Ndr64ProcedureHandleParameter(0, new Ndr64HandleTypeReference(handle_type), 
                0, false, 0, handle_type == Ndr64FormatCharacter.FC64_BIND_GENERIC);
        }

        int number_of_params = proc_format.NumberOfParams;
        IntPtr param_ptr = format_info + RTMarshal.SizeOf<NDR64_PROC_FORMAT>() + proc_format.ExtensionSize;
        NDR64_PARAM_FORMAT[] param_list = context.Reader.ReadArray<NDR64_PARAM_FORMAT>(param_ptr, number_of_params);

        List <Ndr64ProcedureParameter> ps = new();

        bool has_return = proc_format.Flags.HasReturn;
        int param_count = has_return ? number_of_params - 1 : number_of_params;

        for (int param = 0; param < param_count; ++param)
        {
            ps.Add(new Ndr64ProcedureParameter(context, param_list[param], $"p{param}"));
        }

        if (Handle.Explicit && !Handle.Generic)
        {
            // Insert handle into parameter list at the best location.
            if (ps.Count == 0)
            {
                ps.Add(Handle);
            }
            else
            {
                int index = 0;
                while (index < ps.Count)
                {
                    if (ps[index].StackOffset == Handle.StackOffset)
                    {
                        // There already exists the handle parameter, ignore.
                        break;
                    }

                    if (ps[index].StackOffset > Handle.StackOffset)
                    {
                        ps.Insert(index, Handle);
                        break;
                    }
                    index++;
                }
            }
        }

        Params = ps.AsReadOnly();
        if (has_return)
        {
            ReturnValue = new Ndr64ProcedureParameter(context, param_list[param_count], "retval");
        }

        DispatchFunction = dispatch_func;
        if (base_offset != IntPtr.Zero)
        {
            DispatchOffset = (int)(DispatchFunction.ToInt64() - base_offset.ToInt64());
        }
    }
}