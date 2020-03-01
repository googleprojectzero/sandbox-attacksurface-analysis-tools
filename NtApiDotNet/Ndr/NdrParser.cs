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

using NtApiDotNet.Utilities.Memory;
using NtApiDotNet.Win32;
using NtApiDotNet.Win32.Debugger;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Ndr
{
#pragma warning disable 1591
    [Flags]
    [Serializable]
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
    [Serializable]
    public enum NdrInterpreterOptFlags2 : byte
    {
        HasNewCorrDesc = 0x01,
        ClientCorrCheck = 0x02,
        ServerCorrCheck = 0x04,
        HasNotify = 0x08,
        HasNotify2 = 0x10,
        HasComplexReturn = 0x20,
        HasRangeOnConformance = 0x40,
        HasBigByValParam = 0x80,
        Valid = HasNewCorrDesc | ClientCorrCheck | ServerCorrCheck | HasNotify | HasNotify2 | HasRangeOnConformance
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

        internal void FixupLateBoundTypes()
        {
            foreach (var type in Cache.Values)
            {
                type.FixupLateBoundTypes();
            }
        }
    }

    internal class NdrParseContext
    {
        public NdrTypeCache TypeCache { get; }
        public ISymbolResolver SymbolResolver { get; }
        public MIDL_STUB_DESC StubDesc { get; }
        public IntPtr TypeDesc { get; }
        public IMemoryReader Reader { get; }
        public NdrParserFlags Flags { get; }
        public NDR_EXPR_DESC ExprDesc { get; }
        public NdrInterpreterOptFlags2 OptFlags { get; }

        public bool HasFlag(NdrParserFlags flags)
        {
            return (Flags & flags) == flags;
        }

        internal NdrParseContext(NdrTypeCache type_cache, ISymbolResolver symbol_resolver, 
            MIDL_STUB_DESC stub_desc, IntPtr type_desc, NDR_EXPR_DESC expr_desc,
            NdrInterpreterOptFlags2 opt_flags, IMemoryReader reader, NdrParserFlags parser_flags)
        {
            TypeCache = type_cache;
            SymbolResolver = symbol_resolver;
            StubDesc = stub_desc;
            TypeDesc = type_desc;
            ExprDesc = expr_desc;
            OptFlags = opt_flags;
            Reader = reader;
            Flags = parser_flags;
        }
    }

    /// <summary>
    /// Flags for the parser.
    /// </summary>
    [Flags]
    public enum NdrParserFlags
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,
        /// <summary>
        /// Ignore processing any complex user marshal types.
        /// </summary>
        IgnoreUserMarshal = 1,
    }

    /// <summary>
    /// Class to parse NDR data into a structured format.
    /// </summary>
    public sealed class NdrParser
    {
        #region Private Members
        private readonly NdrTypeCache _type_cache;
        private readonly ISymbolResolver _symbol_resolver;
        private readonly IMemoryReader _reader;
        private readonly NdrParserFlags _parser_flags;

        private static NdrRpcServerInterface ReadRpcServerInterface(IMemoryReader reader, RPC_SERVER_INTERFACE server_interface, 
            NdrTypeCache type_cache, ISymbolResolver symbol_resolver, NdrParserFlags parser_flags)
        {
            RPC_DISPATCH_TABLE dispatch_table = server_interface.GetDispatchTable(reader);
            var procs = ReadProcs(reader, server_interface.GetServerInfo(reader), 0, 
                dispatch_table.DispatchTableCount, type_cache, symbol_resolver, null, parser_flags);
            return new NdrRpcServerInterface(server_interface.InterfaceId, server_interface.TransferSyntax, procs,
                server_interface.GetProtSeq(reader).Select(s => new NdrProtocolSequenceEndpoint(s, reader)));
        }

        private static IEnumerable<NdrProcedureDefinition> ReadProcs(IMemoryReader reader, MIDL_SERVER_INFO server_info, int start_offset,
            int dispatch_count, NdrTypeCache type_cache, ISymbolResolver symbol_resolver, IList<string> names, NdrParserFlags parser_flags)
        {
            RPC_SYNTAX_IDENTIFIER transfer_syntax = server_info.GetTransferSyntax(reader);

            IntPtr proc_str = IntPtr.Zero;
            IntPtr fmt_str_ofs = IntPtr.Zero;

            if (transfer_syntax.SyntaxGUID != NdrNativeUtils.DCE_TransferSyntax)
            {
                MIDL_SYNTAX_INFO[] syntax_info = server_info.GetSyntaxInfo(reader);
                if (!syntax_info.Any(s => s.TransferSyntax.SyntaxGUID == NdrNativeUtils.DCE_TransferSyntax))
                {
                    throw new NdrParserException("Can't parse NDR64 syntax data");
                }
                MIDL_SYNTAX_INFO dce_syntax_info = syntax_info.First(s => s.TransferSyntax.SyntaxGUID == NdrNativeUtils.DCE_TransferSyntax);
                proc_str = dce_syntax_info.ProcString;
                fmt_str_ofs = dce_syntax_info.FmtStringOffset;
            }
            else
            {
                proc_str = server_info.ProcString;
                fmt_str_ofs = server_info.FmtStringOffset;
            }

            IntPtr[] dispatch_funcs = server_info.GetDispatchTable(reader, dispatch_count);
            MIDL_STUB_DESC stub_desc = server_info.GetStubDesc(reader);
            IntPtr type_desc = stub_desc.pFormatTypes;
            NDR_EXPR_DESC expr_desc = stub_desc.GetExprDesc(reader);
            List<NdrProcedureDefinition> procs = new List<NdrProcedureDefinition>();
            if (fmt_str_ofs != IntPtr.Zero)
            {
                for (int i = start_offset; i < dispatch_count; ++i)
                {
                    int fmt_ofs = reader.ReadInt16(fmt_str_ofs + i * 2);
                    if (fmt_ofs >= 0)
                    {
                        string name = null;
                        if (names != null)
                        {
                            name = names[i - start_offset];
                        }
                        procs.Add(new NdrProcedureDefinition(reader, type_cache, symbol_resolver,
                            stub_desc, proc_str + fmt_ofs, type_desc, expr_desc, dispatch_funcs[i], name, parser_flags));
                    }
                }
            }
            return procs.AsReadOnly();
        }

        private void ReadTypes(IntPtr midl_type_pickling_info_ptr, IntPtr midl_stub_desc_ptr, IEnumerable<int> fmt_offsets)
        {
            if (midl_type_pickling_info_ptr == IntPtr.Zero)
            {
                throw new ArgumentException("Must specify the MIDL_TYPE_PICKLING_INFO pointer");
            }

            if (midl_stub_desc_ptr == IntPtr.Zero)
            {
                throw new ArgumentException("Must specify the MIDL_STUB_DESC pointer");
            }

            var pickle_info = _reader.ReadStruct<MIDL_TYPE_PICKLING_INFO>(midl_type_pickling_info_ptr);
            if (pickle_info.Version != 0x33205054)
            {
                throw new ArgumentException($"Unsupported picking type version {pickle_info.Version:X}");
            }

            var flags = pickle_info.Flags.HasFlag(MidlTypePicklingInfoFlags.NewCorrDesc) ? NdrInterpreterOptFlags2.HasNewCorrDesc : 0;
            MIDL_STUB_DESC stub_desc = _reader.ReadStruct<MIDL_STUB_DESC>(midl_stub_desc_ptr);
            NdrParseContext context = new NdrParseContext(_type_cache, null, stub_desc, stub_desc.pFormatTypes, stub_desc.GetExprDesc(_reader),
                flags, _reader, NdrParserFlags.IgnoreUserMarshal);
            foreach (var i in fmt_offsets)
            {
                NdrBaseTypeReference.Read(context, i);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void GetProxyDllInfo(out IntPtr pInfo, out IntPtr pId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DllGetClassObject(ref Guid clsid, ref Guid riid, out IntPtr ppv);

        private IList<NdrProcedureDefinition> ReadProcs(Guid base_iid, CInterfaceStubHeader stub)
        {
            int start_ofs = 3;
            if (base_iid == NdrNativeUtils.IID_IDispatch)
            {
                start_ofs = 7;
            }

            return ReadFromMidlServerInfo(stub.pServerInfo, start_ofs, stub.DispatchTableCount).ToList().AsReadOnly();
        }

        private static IntPtr FindProxyDllInfo(SafeLoadLibraryHandle lib, Guid clsid)
        {
            try
            {
                GetProxyDllInfo get_proxy_dllinfo = lib.GetFunctionPointer<GetProxyDllInfo>();
                get_proxy_dllinfo(out IntPtr pInfo, out IntPtr pId);
                return pInfo;
            }
            catch (Win32Exception)
            {
            }

            IntPtr psfactory = IntPtr.Zero;
            try
            {
                DllGetClassObject dll_get_class_object = lib.GetFunctionPointer<DllGetClassObject>();
                Guid IID_IPSFactoryBuffer = NdrNativeUtils.IID_IPSFactoryBuffer;

                int hr = dll_get_class_object(ref clsid, ref IID_IPSFactoryBuffer, out psfactory);
                if (hr != 0)
                {
                    throw new Win32Exception(hr);
                }

                // The PSFactoryBuffer object seems to be structured like on Win10 at least.
                // VTABLE*
                // Reference Count
                // ProxyFileInfo*

                IntPtr pInfo = System.Runtime.InteropServices.Marshal.ReadIntPtr(psfactory, 2 * IntPtr.Size);
                // TODO: Should add better checks here, 
                // for example VTable should be in COMBASE and the pointer should be in the
                // server DLL's rdata section. But this is probably good enough for now.
                using (SafeLoadLibraryHandle module = SafeLoadLibraryHandle.GetModuleHandle(pInfo))
                {
                    if (module == null || lib.DangerousGetHandle() != module.DangerousGetHandle())
                    {
                        return IntPtr.Zero;
                    }
                }

                return pInfo;
            }
            catch (Win32Exception)
            {
                return IntPtr.Zero;
            }
            finally
            {
                if (psfactory != IntPtr.Zero)
                {
                    System.Runtime.InteropServices.Marshal.Release(psfactory);
                }
            }
        }

        private bool InitFromProxyFileInfo(ProxyFileInfo proxy_file_info, IList<NdrComProxyDefinition> interfaces, HashSet<Guid> iid_set)
        {
            string[] names = proxy_file_info.GetNames(_reader);
            CInterfaceStubHeader[] stubs = proxy_file_info.GetStubs(_reader);
            Guid[] base_iids = proxy_file_info.GetBaseIids(_reader);
            for (int i = 0; i < names.Length; ++i)
            {
                Guid iid = stubs[i].GetIid(_reader);
                if (iid_set.Count == 0 || iid_set.Contains(iid))
                {
                    interfaces.Add(new NdrComProxyDefinition(names[i], iid,
                        base_iids[i], stubs[i].DispatchTableCount, ReadProcs(base_iids[i], stubs[i])));
                }
            }
            return true;
        }

        private bool InitFromProxyFileInfoArray(IntPtr proxy_file_info_array, IList<NdrComProxyDefinition> interfaces, HashSet<Guid> iid_set)
        {
            foreach (var file_info in _reader.EnumeratePointerList<ProxyFileInfo>(proxy_file_info_array))
            {
                if (!InitFromProxyFileInfo(file_info, interfaces, iid_set))
                {
                    return false;
                }
            }

            return true;
        }

        private bool InitFromFile(string path, Guid clsid, IList<NdrComProxyDefinition> interfaces, IEnumerable<Guid> iids)
        {
            if (iids == null)
            {
                iids = new Guid[0];
            }
            HashSet<Guid> iid_set = new HashSet<Guid>(iids);
            using (SafeLoadLibraryHandle lib = SafeLoadLibraryHandle.LoadLibrary(path))
            {
                _symbol_resolver?.LoadModule(path, lib.DangerousGetHandle());
                IntPtr pInfo = FindProxyDllInfo(lib, clsid);
                if (pInfo == IntPtr.Zero)
                {
                    return false;
                }

                return InitFromProxyFileInfoArray(pInfo, interfaces, iid_set);
            }
        }

        private static void CheckSymbolResolver(NtProcess process, ISymbolResolver symbol_resolver)
        {
            int pid = process == null ? NtProcess.Current.ProcessId : process.ProcessId;
            if (symbol_resolver is DbgHelpSymbolResolver dbghelp_resolver)
            {
                if (dbghelp_resolver.Process.ProcessId != pid)
                {
                    throw new ArgumentException("Symbol resolver must be for the same process as the passed process");
                }
            }
        }

        [HandleProcessCorruptedStateExceptions]
        private static T RunWithAccessCatch<T>(Func<T> func)
        {
            try
            {
                return func();
            }
            catch (Exception ex)
            {
                if (ex is NdrParserException)
                {
                    // Re-throw if already is an NDR parser exception.
                    throw;
                }

                throw new NdrParserException("Error while parsing NDR structures");
            }
        }

        private static void RunWithAccessCatch(Action func)
        {
            RunWithAccessCatch(() =>
            {
                func();
                return 0;
            }
            );
        }

        private static IMemoryReader CreateReader(NtProcess process)
        {
            if (process == null || process.ProcessId == NtProcess.Current.ProcessId)
            {
                return new CurrentProcessMemoryReader();
            }
            else
            {
                return ProcessMemoryReader.Create(process);
            }
        }

        #endregion

        #region Internal Members
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="reader">Memory reader to parse from.</param>
        /// <param name="process">Process to read from.</param>
        /// <param name="symbol_resolver">Specify a symbol resolver to use for looking up symbols.</param>
        /// <param name="parser_flags">Flags which affect the parsing operation.</param>
        internal NdrParser(IMemoryReader reader, NtProcess process, ISymbolResolver symbol_resolver, NdrParserFlags parser_flags)
        {
            CheckSymbolResolver(process, symbol_resolver);
            _reader = reader;
            _symbol_resolver = symbol_resolver;
            _type_cache = new NdrTypeCache();
            _parser_flags = parser_flags;
        }
        #endregion

        #region Public Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="process">Process to parse from.</param>
        /// <param name="symbol_resolver">Specify a symbol resolver to use for looking up symbols.</param>
        public NdrParser(NtProcess process, ISymbolResolver symbol_resolver) 
            : this(process, symbol_resolver, NdrParserFlags.None)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="process">Process to parse from.</param>
        /// <param name="symbol_resolver">Specify a symbol resolver to use for looking up symbols.</param>
        /// <param name="parser_flags">Flags which affect the parsing operation.</param>
        public NdrParser(NtProcess process, ISymbolResolver symbol_resolver, NdrParserFlags parser_flags) 
            : this(CreateReader(process), process, symbol_resolver, parser_flags)
        {
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

        #endregion

        #region Public Methods

        /// <summary>
        /// Read COM proxy information from a ProxyFileInfo structure.
        /// </summary>
        /// <param name="proxy_file_info">The address of the ProxyFileInfo structure.</param>
        /// <returns>The list of parsed proxy definitions.</returns>
        public IEnumerable<NdrComProxyDefinition> ReadFromProxyFileInfo(IntPtr proxy_file_info)
        {
            List<NdrComProxyDefinition> interfaces = new List<NdrComProxyDefinition>();
            if (!RunWithAccessCatch(() => InitFromProxyFileInfo(_reader.ReadStruct<ProxyFileInfo>(proxy_file_info), interfaces, new HashSet<Guid>())))
            {
                throw new NdrParserException("Can't find proxy information in server DLL");
            }

            return interfaces.AsReadOnly();
        }

        /// <summary>
        /// Read COM proxy information from an array of pointers to ProxyFileInfo structures.
        /// </summary>
        /// <param name="proxy_file_info_array">The address of an array of pointers to ProxyFileInfo structures. The last pointer should be NULL.</param>
        /// <returns>The list of parsed proxy definitions.</returns>
        public IEnumerable<NdrComProxyDefinition> ReadFromProxyFileInfoArray(IntPtr proxy_file_info_array)
        {
            List<NdrComProxyDefinition> interfaces = new List<NdrComProxyDefinition>();
            if (!RunWithAccessCatch(() => InitFromProxyFileInfoArray(proxy_file_info_array, interfaces, new HashSet<Guid>())))
            {
                throw new NdrParserException("Can't find proxy information in server DLL");
            }

            return interfaces.AsReadOnly();
        }

        /// <summary>
        /// Read COM proxy information from a file.
        /// </summary>
        /// <param name="path">The path to the DLL containing the proxy.</param>
        /// <param name="clsid">Optional CLSID for the proxy class.</param>
        /// <param name="iids">List of IIDs to parse.</param>
        /// <returns>The list of parsed proxy definitions.</returns>
        public IEnumerable<NdrComProxyDefinition> ReadFromComProxyFile(string path, Guid clsid, IEnumerable<Guid> iids)
        {
            if (!_reader.InProcess)
            {
                throw new NdrParserException("Can't parse COM proxy information from a file out of process.");
            }

            List<NdrComProxyDefinition> interfaces = new List<NdrComProxyDefinition>();
            if (!RunWithAccessCatch(() => InitFromFile(path, clsid, interfaces, iids)))
            {
                throw new NdrParserException("Can't find proxy information in server DLL");
            }

            return interfaces.AsReadOnly();
        }

        /// <summary>
        /// Read COM proxy information from a file.
        /// </summary>
        /// <param name="path">The path to the DLL containing the proxy.</param>
        /// <param name="clsid">Optional CLSID for the proxy class.</param>
        /// <returns>The list of parsed proxy definitions.</returns>
        public IEnumerable<NdrComProxyDefinition> ReadFromComProxyFile(string path, Guid clsid)
        {
            return ReadFromComProxyFile(path, clsid, null);
        }

        /// <summary>
        /// Read COM proxy information from a file.
        /// </summary>
        /// <param name="path">The path to the DLL containing the proxy.</param>
        /// <returns>The list of parsed proxy definitions.</returns>
        public IEnumerable<NdrComProxyDefinition> ReadFromComProxyFile(string path)
        {
            return ReadFromComProxyFile(path, Guid.Empty);
        }

        /// <summary>
        /// Parse NDR content from an RPC_SERVER_INTERFACE structure in memory.
        /// </summary>
        /// <param name="server_interface">Pointer to the RPC_SERVER_INTERFACE.</param>
        /// <returns>The parsed NDR content.</returns>
        public NdrRpcServerInterface ReadFromRpcServerInterface(IntPtr server_interface)
        {
            return RunWithAccessCatch(() => ReadRpcServerInterface(_reader, 
                _reader.ReadStruct<RPC_SERVER_INTERFACE>(server_interface), _type_cache, _symbol_resolver, _parser_flags));
        }

        /// <summary>
        /// Parse NDR content from an RPC_SERVER_INTERFACE structure in memory. Deprecated.
        /// </summary>
        /// <param name="server_interface">Pointer to the RPC_SERVER_INTERFACE.</param>
        /// <returns>The parsed NDR content.</returns>
        [Obsolete("Use ReadFromRpcServerInterface instead.")]
        public NdrRpcServerInterface ReadRpcServerInterface(IntPtr server_interface)
        {
            return ReadFromRpcServerInterface(server_interface);
        }

        /// <summary>
        /// Parse NDR content from an RPC_SERVER_INTERFACE structure in memory.
        /// </summary>
        /// <param name="dll_path">The path to a DLL containing the RPC_SERVER_INTERFACE.</param>
        /// <param name="offset">Offset to the RPC_SERVER_INTERFACE from the base of the DLL.</param>
        /// <returns>The parsed NDR content.</returns>
        public NdrRpcServerInterface ReadFromRpcServerInterface(string dll_path, int offset)
        {
            using (var lib = SafeLoadLibraryHandle.LoadLibrary(dll_path, LoadLibraryFlags.DontResolveDllReferences))
            {
                _symbol_resolver?.LoadModule(dll_path, lib.DangerousGetHandle());
                return ReadFromRpcServerInterface(lib.DangerousGetHandle() + offset);
            }
        }

        /// <summary>
        /// Parse NDR procedures from an MIDL_SERVER_INFO structure in memory.
        /// </summary>
        /// <param name="server_info">Pointer to the MIDL_SERVER_INFO.</param>
        /// <param name="dispatch_count">Number of dispatch functions to parse.</param>
        /// <param name="start_offset">The start offset to parse from. This is used for COM where the first few proxy stubs are not implemented.</param>
        /// <param name="names">List of names for the valid procedures. Should either be null or a list equal in size to dispatch_count - start_offset.</param>
        /// <returns>The parsed NDR content.</returns>
        public IEnumerable<NdrProcedureDefinition> ReadFromMidlServerInfo(IntPtr server_info, int start_offset, int dispatch_count, IList<string> names)
        {
            if (names != null && names.Count != (dispatch_count - start_offset))
            {
                throw new NdrParserException("List of names must be same size of the total methods to parse");
            }
            return RunWithAccessCatch(() => ReadProcs(_reader, _reader.ReadStruct<MIDL_SERVER_INFO>(server_info),
                start_offset, dispatch_count, _type_cache, _symbol_resolver, names, _parser_flags));
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
            return RunWithAccessCatch(() => ReadProcs(_reader, _reader.ReadStruct<MIDL_SERVER_INFO>(server_info),
                start_offset, dispatch_count, _type_cache, _symbol_resolver, null, _parser_flags));
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// List of parsed types from the NDR.
        /// </summary>
        public IEnumerable<NdrBaseTypeReference> Types
        {
            get
            {
                _type_cache.FixupLateBoundTypes();
                return _type_cache.Cache.Values;
            }
        }

        /// <summary>
        /// List of parsed complex types from the NDR.
        /// </summary>
        public IEnumerable<NdrComplexTypeReference> ComplexTypes { get { return Types.OfType<NdrComplexTypeReference>(); } }

        #endregion

        #region Static Methods
        /// <summary>
        /// Parse NDR complex type information from a pickling structure. Used to extract explicit Encode/Decode method information.
        /// </summary>
        /// <param name="process">The process to read from.</param>
        /// <param name="midl_type_pickling_info">Pointer to the MIDL_TYPE_PICKLING_INFO structure.</param>
        /// <param name="midl_stub_desc">The pointer to the MIDL_STUB_DESC structure.</param>
        /// <param name="start_offsets">Offsets into the format string to the start of the types.</param>
        /// <returns>The list of complex types.</returns>
        /// <remarks>This function is used to extract type information for calls to NdrMesTypeDecode2. MIDL_TYPE_PICKLING_INFO is the second parameter,
        /// MIDL_STUB_DESC is the third (minus the offset).</remarks>
        public static IEnumerable<NdrComplexTypeReference> ReadPicklingComplexTypes(NtProcess process, IntPtr midl_type_pickling_info, IntPtr midl_stub_desc, params int[] start_offsets)
        {
            if (start_offsets.Length == 0)
            {
                return new NdrComplexTypeReference[0];
            }

            NdrParser parser = new NdrParser(process, null, NdrParserFlags.IgnoreUserMarshal);
            RunWithAccessCatch(() => parser.ReadTypes(midl_type_pickling_info, midl_stub_desc, start_offsets));
            return parser.ComplexTypes;
        }

        /// <summary>
        /// Parse NDR complex type information from a pickling structure. Used to extract explicit Encode/Decode method information.
        /// </summary>
        /// <param name="midl_type_pickling_info">Pointer to the MIDL_TYPE_PICKLING_INFO structure.</param>
        /// <param name="midl_stub_desc">The pointer to the MIDL_STUB_DESC structure.</param>
        /// <param name="start_offsets">Offsets into the format string to the start of the types.</param>
        /// <returns>The list of complex types.</returns>
        /// <remarks>This function is used to extract type information for calls to NdrMesTypeDecode2. MIDL_TYPE_PICKLING_INFO is the second parameter,
        /// MIDL_STUB_DESC is the third (minus the offset).</remarks>
        public static IEnumerable<NdrComplexTypeReference> ReadPicklingComplexTypes(IntPtr midl_type_pickling_info, IntPtr midl_stub_desc, params int[] start_offsets)
        {
            return ReadPicklingComplexTypes(null, midl_type_pickling_info, midl_stub_desc, start_offsets);
        }

        #endregion
    }
}
