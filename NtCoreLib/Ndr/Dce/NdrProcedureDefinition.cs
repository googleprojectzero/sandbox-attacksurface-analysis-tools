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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Ndr.Interop;
using NtCoreLib.Ndr.Parser;
using NtCoreLib.Utilities.Memory;
using NtCoreLib.Win32.Debugger.Symbols;
using System;
using System.Collections.Generic;
using System.IO;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public class NdrProcedureDefinition
{
    public string Name { get; set; }
    public IList<NdrProcedureParameter> Params { get; }
    public NdrProcedureParameter ReturnValue { get; }
    public NdrProcedureHandleParameter Handle { get; }
    public uint RpcFlags { get; }
    public int ProcNum { get; }
    public int StackSize { get; }
    public bool HasAsyncHandle => InterpreterFlags.HasFlag(NdrInterpreterOptFlags.HasAsyncHandle);
    public IntPtr DispatchFunction { get; }
    public int DispatchOffset { get; }
    public NdrInterpreterOptFlags InterpreterFlags { get; }
    public ushort ConstantClientBufferSize { get; }
    public ushort ConstantServerBufferSize { get; }

    internal NdrProcedureDefinition(IMemoryReader mem_reader, NdrTypeCache type_cache,
        ISymbolResolver symbol_resolver, MIDL_STUB_DESC stub_desc,
        IntPtr proc_desc, IntPtr type_desc, NDR_EXPR_DESC expr_desc, IntPtr dispatch_func,
        IntPtr base_offset, string name, NdrParserFlags parser_flags, 
        Dictionary<int, NdrUnionArms> union_arms_cache)
    {
        BinaryReader reader = new(mem_reader.GetStream(proc_desc));
        NdrFormatCharacter handle_type = (NdrFormatCharacter)reader.ReadByte();
        NdrInterpreterFlags old_oi_flags = (NdrInterpreterFlags)reader.ReadByte();

        if ((old_oi_flags & NdrInterpreterFlags.HasRpcFlags) == NdrInterpreterFlags.HasRpcFlags)
        {
            RpcFlags = reader.ReadUInt32();
        }

        ProcNum = reader.ReadUInt16();

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

        StackSize = reader.ReadUInt16();
        if (handle_type == 0)
        {
            // read out handle type.
            handle_type = (NdrFormatCharacter)reader.ReadByte();
            NdrHandleTypeFlags flags = (NdrHandleTypeFlags)reader.ReadByte();
            NdrParamAttributes attrs = 0;

            ushort handle_offset = reader.ReadUInt16();
            NdrBaseTypeReference base_type = new NdrSimpleTypeReference(handle_type);
            
            if (handle_type == NdrFormatCharacter.FC_BIND_PRIMITIVE)
            {
                flags = flags != 0 ? NdrHandleTypeFlags.IsViaPtr : 0;
            }
            else if (handle_type == NdrFormatCharacter.FC_BIND_GENERIC)
            {
                // Remove the size field, we might do something with this later.
                flags = (NdrHandleTypeFlags)((byte)flags & 0xF0);
                // Read out the remaining data.
                reader.ReadByte();
                reader.ReadByte();
            }
            else if (handle_type == NdrFormatCharacter.FC_BIND_CONTEXT)
            {
                if (flags.HasFlagSet(NdrHandleTypeFlags.IsIn))
                    attrs |= NdrParamAttributes.IsIn;
                if (flags.HasFlagSet(NdrHandleTypeFlags.IsOut))
                    attrs |= NdrParamAttributes.IsOut;
                if (flags.HasFlagSet(NdrHandleTypeFlags.IsReturn))
                    attrs |= NdrParamAttributes.IsReturn;

                // Read out the remaining data.
                reader.ReadByte();
                reader.ReadByte();
            }
            else
            {
                throw new ArgumentException($"Unsupported explicit handle type {handle_type}");
            }
            Handle = new NdrProcedureHandleParameter(attrs == 0 ? NdrParamAttributes.IsIn : attrs,
                    (flags & NdrHandleTypeFlags.IsViaPtr) != 0 ? new NdrPointerTypeReference(base_type)
                        : base_type, handle_offset, true, flags, handle_type == NdrFormatCharacter.FC_BIND_GENERIC);
        }
        else
        {
            Handle = new NdrProcedureHandleParameter(0, new NdrSimpleTypeReference(handle_type), 0, false, 0, false);
        }

        ConstantClientBufferSize = reader.ReadUInt16();
        ConstantServerBufferSize = reader.ReadUInt16();
        InterpreterFlags = (NdrInterpreterOptFlags)reader.ReadByte();
        int number_of_params = reader.ReadByte();

        NdrProcHeaderExts exts = new();
        if ((InterpreterFlags & NdrInterpreterOptFlags.HasExtensions) == NdrInterpreterOptFlags.HasExtensions)
        {
            int ext_size = reader.ReadByte();
            reader.BaseStream.Position -= 1;
            // Read out extension bytes.
            byte[] extension = reader.ReadAll(ext_size);
            if (System.Runtime.InteropServices.Marshal.SizeOf(typeof(NdrProcHeaderExts)) <= ext_size)
            {
                using var buffer = new SafeStructureInOutBuffer<NdrProcHeaderExts>(ext_size, false);
                buffer.WriteArray(0, extension, 0, ext_size);
                exts = buffer.Result;
            }
        }

        NdrParseContext context = new(type_cache, symbol_resolver, stub_desc, type_desc, 
            expr_desc, exts.Flags2, mem_reader, parser_flags, union_arms_cache);
        List<NdrProcedureParameter> ps = new();

        bool has_return = InterpreterFlags.HasFlag(NdrInterpreterOptFlags.HasReturn);
        int param_count = has_return ? number_of_params - 1 : number_of_params;
        for (int param = 0; param < param_count; ++param)
        {
            ps.Add(new NdrProcedureParameter(context, reader, $"p{param}"));
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
                    if (ps[index].Offset == Handle.Offset)
                    {
                        // There already exists the handle parameter, ignore.
                        break;
                    }

                    if (ps[index].Offset > Handle.Offset)
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
            ReturnValue = new NdrProcedureParameter(context, reader, "retval");
        }

        DispatchFunction = dispatch_func;
        if (base_offset != IntPtr.Zero)
        {
            DispatchOffset = (int)(DispatchFunction.ToInt64() - base_offset.ToInt64());
        }
    }
}

#pragma warning restore 1591
