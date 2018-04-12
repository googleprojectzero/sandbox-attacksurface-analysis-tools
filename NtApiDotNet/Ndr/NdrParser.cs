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

using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;

namespace NtApiDotNet.Ndr
{
#pragma warning disable 1591
    [Flags]
    public enum NdrInterpreterOptFlags : byte
    {
        ServerMustSize = 0x01,
        ClientMustSize = 0x02,
        HasReturn = 0x04,
        HasPipes = 0x08,
        HasAsyncUuid = 0x20,
        HasExtensions = 0x40,
        HasAsyncHandle = 0x80,
    }

    [Flags]
    public enum NdrInterpreterOptFlags2 : byte
    {
        HasNewCorrDesc = 0x01,
        ClientCorrCheck = 0x02,
        ServerCorrCheck = 0x04,
        HasNotify = 0x08,
        HasNotify2 = 0x10,
        Unknown20 = 0x20,
        ExtendedCorrDesc = 0x40,
        Unknown80 = 0x80,
        Valid = HasNewCorrDesc | ClientCorrCheck | ServerCorrCheck | HasNotify | HasNotify2 | ExtendedCorrDesc
    }

#pragma warning restore 1591

    internal class NdrTypeCache
    {
        private int _complex_id;

        public Dictionary<IntPtr, NdrBaseTypeReference> Cache { get; }

        public int GetNextComplexId()
        {
            return _complex_id++;
        }

        public NdrTypeCache()
        {
            Cache = new Dictionary<IntPtr, NdrBaseTypeReference>();
        }
    }

    internal class NdrParseContext
    {
        public NdrTypeCache TypeCache { get; private set; }
        public ISymbolResolver SymbolResolver { get; private set; }
        public MIDL_STUB_DESC StubDesc { get; private set; }
        public IntPtr TypeDesc { get; private set; }
        public int CorrDescSize { get; private set; }
        public IMemoryReader Reader { get; private set;}

        internal NdrParseContext(NdrTypeCache type_cache, ISymbolResolver symbol_resolver, 
            MIDL_STUB_DESC stub_desc, IntPtr type_desc, int desc_size, IMemoryReader reader)
        {
            TypeCache = type_cache;
            SymbolResolver = symbol_resolver;
            StubDesc = stub_desc;
            TypeDesc = type_desc;
            CorrDescSize = desc_size;
            Reader = reader;
        }
    }

    /// <summary>
    /// Class to parse NDR data into a structured format.
    /// </summary>
    public sealed class NdrParser
    {
        private readonly NdrTypeCache _type_cache;
        private readonly ISymbolResolver _symbol_resolver;
        private readonly IMemoryReader _reader;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="process">Process to parse from.</param>
        /// <param name="symbol_resolver">Specify a symbol resolver to use for looking up symbols.</param>
        public NdrParser(NtProcess process, ISymbolResolver symbol_resolver)
        {
            if (process == null || process.ProcessId == NtProcess.Current.ProcessId)
            {
                _reader = new CurrentProcessMemoryReader();
            }
            else
            {
                _reader = new ProcessMemoryReader(process);
            }
            _symbol_resolver = symbol_resolver;
            _type_cache = new NdrTypeCache();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="symbol_resolver">Specify a symbol resolver to use for looking up symbols.</param>
        public NdrParser(ISymbolResolver symbol_resolver) : this(null, symbol_resolver)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="process">Process to parse from.</param>
        public NdrParser(NtProcess process) : this(process, null)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public NdrParser() : this(null, null)
        {
        }

        private static NdrRpcServerInterface ReadRpcServerInterface(IMemoryReader reader, RPC_SERVER_INTERFACE server_interface, NdrTypeCache type_cache, ISymbolResolver symbol_resolver)
        {
            RPC_DISPATCH_TABLE dispatch_table = server_interface.GetDispatchTable(reader);
            var procs = ReadProcs(reader, server_interface.GetServerInfo(reader), 0, dispatch_table.DispatchTableCount, type_cache, symbol_resolver);
            return new NdrRpcServerInterface(server_interface.InterfaceId, server_interface.TransferSyntax, procs);
        }

        private static IEnumerable<NdrProcedureDefinition> ReadProcs(IMemoryReader reader, MIDL_SERVER_INFO server_info, int start_offset, 
            int dispatch_count, NdrTypeCache type_cache, ISymbolResolver symbol_resolver)
        {
            IntPtr[] dispatch_funcs = server_info.GetDispatchTable(reader, dispatch_count);
            MIDL_STUB_DESC stub_desc = server_info.GetStubDesc(reader);
            IntPtr type_desc = stub_desc.pFormatTypes;
            List<NdrProcedureDefinition> procs = new List<NdrProcedureDefinition>();
            for(int i = start_offset; i < dispatch_count; ++i)
            {
                int fmt_ofs = reader.ReadInt16(server_info.FmtStringOffset + i * 2);
                if (fmt_ofs >= 0)
                {
                    procs.Add(new NdrProcedureDefinition(reader, type_cache, symbol_resolver, stub_desc, server_info.ProcString + fmt_ofs, type_desc, dispatch_funcs[i]));
                }
            }
            return procs.AsReadOnly();
        }

        /// <summary>
        /// Parse NDR content from an RPC_SERVER_INTERFACE structure in memory.
        /// </summary>
        /// <param name="server_interface">Pointer to the RPC_SERVER_INTERFACE.</param>
        /// <returns>The parsed NDR content.</returns>
        public NdrRpcServerInterface ReadRpcServerInterface(IntPtr server_interface)
        {
            return ReadRpcServerInterface(_reader, _reader.ReadStruct<RPC_SERVER_INTERFACE>(server_interface), _type_cache, _symbol_resolver);
        }

        /// <summary>
        /// Parse NDR procedures from an MIDL_SERVER_INFO structure in memory.
        /// </summary>
        /// <param name="server_info">Pointer to the MIDL_SERVER_INFO.</param>
        /// <param name="dispatch_count">Number of dispatch functions to parse.</param>
        /// <param name="start_offset">The start offset to parse from. This is used for COM where the first few proxy stubs are not implemented.</param>
        /// <returns>The parsed NDR content.</returns>
        public IEnumerable<NdrProcedureDefinition> ReadFromMidlServerInfo(IntPtr server_info, int start_offset, int dispatch_count)
        {
            return ReadProcs(_reader, _reader.ReadStruct<MIDL_SERVER_INFO>(server_info), start_offset, dispatch_count, _type_cache, _symbol_resolver);
        }

        /// <summary>
        /// List of parsed types from the NDR.
        /// </summary>
        public IEnumerable<NdrBaseTypeReference> Types { get { return _type_cache.Cache.Values; } }
    }
}
