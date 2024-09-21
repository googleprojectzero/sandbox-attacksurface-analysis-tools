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

using NtCoreLib.Ndr.Com;
using NtCoreLib.Ndr.Dce;
using NtCoreLib.Ndr.Interop;
using NtCoreLib.Ndr.Ndr64;
using NtCoreLib.Ndr.Rpc;
using NtCoreLib.Utilities.Memory;
using NtCoreLib.Win32.Debugger.Symbols;
using NtCoreLib.Win32.Loader;
using NtCoreLib.Win32.Rpc.Client.Builder;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using RTMarshal = System.Runtime.InteropServices.Marshal;

namespace NtCoreLib.Ndr.Parser;

/// <summary>
/// Class to parse NDR data into a structured format.
/// </summary>
public sealed class NdrParser
{
    #region Private Members
    private readonly ISymbolResolver _symbol_resolver;
    private readonly IMemoryReader _reader;
    private readonly NdrParserFlags _parser_flags;

    private static RpcServerInterface ReadRpcServerInterface(IMemoryReader reader, RPC_SERVER_INTERFACE server_interface, 
        ISymbolResolver symbol_resolver, NdrParserFlags parser_flags, IntPtr base_address)
    {
        RPC_DISPATCH_TABLE dispatch_table = server_interface.GetDispatchTable(reader);
        IEnumerable<MidlSyntaxInfo> procs = ReadProcs(reader, server_interface.GetServerInfo(reader), 0,
            dispatch_table.DispatchTableCount, symbol_resolver, null, parser_flags, base_address, null, null);
        return new RpcServerInterface(server_interface.InterfaceId, procs,
            server_interface.GetProtSeq(reader).Select(s => new RpcProtocolSequenceEndpoint(s, reader)));
    }

    private static UserDefinedTypeInformation GetUDTType(TypeInformation type_info)
    {
        if (type_info is PointerTypeInformation pointer_type)
        {
            return GetUDTType(pointer_type.PointerType);
        }

        if (type_info is ArrayTypeInformation array_type)
        {
            return GetUDTType(array_type.ArrayType);
        }

        return type_info as UserDefinedTypeInformation;
    }

    private static NdrComplexTypeReference GetComplexType(NdrBaseTypeReference type_reference)
    {
        if (type_reference is NdrPointerTypeReference pointer_type)
        {
            return GetComplexType(pointer_type.Type);
        }

        if (type_reference is NdrBaseArrayTypeReference array_type)
        {
            return GetComplexType(array_type.ElementType);
        }

        return type_reference as NdrComplexTypeReference;
    }

    private static void UpdateComplexTypes(Dictionary<NdrComplexTypeReference, UserDefinedTypeInformation> complex_types,
        TypeInformation type_info, NdrBaseTypeReference type_reference)
    {
        var udt = GetUDTType(type_info);
        var complex = GetComplexType(type_reference);
        if (udt != null && complex != null && !complex_types.ContainsKey(complex))
        {
            complex_types[complex] = udt;
        }
    }

    private static void FixupStructureType(HashSet<NdrComplexTypeReference> fixup_set, NdrBaseStructureTypeReference complex_type, UserDefinedTypeInformation udt)
    {
        // Ignore union types.
        if (udt.Union)
            return;
        var members = complex_type.Members.ToList();
        var udt_members = udt.UniqueMembers;
        if (members.Count != udt_members.Count)
            return;

        for (int i = 0; i < members.Count; ++i)
        {
            var member_complex = GetComplexType(members[i].MemberType);
            if (udt_members[i].Count == 1)
            {
                var udt_member = udt_members[i][0];
                var member_udt = GetUDTType(udt_member.Type);
                if (member_udt != null && member_complex != null)
                {
                    FixupComplexType(fixup_set, member_complex, member_udt);
                }
                members[i].Name = udt_member.Name;
            }
            else if (member_complex is NdrUnionTypeReference union_type && fixup_set.Add(member_complex))
            {
                members[i].Name = $"_Union{i}";
                member_complex.Name = $"{CodeGenUtils.MakeIdentifier(udt.Name)}_Union{i}";
                FixupUnionTypeMembers(fixup_set, union_type.Arms.Arms.ToList(), udt_members[i]);
            }
        }
    }

    private static void FixupUnionTypeMembers(HashSet<NdrComplexTypeReference> fixup_set, List<NdrUnionArm> members,
        IReadOnlyList<UserDefinedTypeMember> udt_members)
    {
        if (members.Count != udt_members.Count)
            return;
        for (int i = 0; i < members.Count; ++i)
        {
            members[i].Name = udt_members[i].Name;
            var member_udt = GetUDTType(udt_members[i].Type);
            var member_complex = GetComplexType(members[i].ArmType);
            if (member_udt != null && member_complex != null)
            {
                FixupComplexType(fixup_set, member_complex, member_udt);
            }
        }
    }

    private static void FixupUnionType(HashSet<NdrComplexTypeReference> fixup_set, NdrUnionTypeReference union_type, UserDefinedTypeInformation udt)
    {
        var members = union_type.Arms.Arms.ToList();
        if (union_type.NonEncapsulated)
        {
            if (!udt.Union)
                return;
        }
        else
        {
            if (udt.Union)
                return;
            if (udt.Members.Count != 2 || udt.Members[1].Type is not UserDefinedTypeInformation sub_union_type || !sub_union_type.Union)
                return;
            union_type.SelectorName = udt.Members[0].Name;
            udt = sub_union_type;
        }

        FixupUnionTypeMembers(fixup_set, members, udt.Members.ToList());
    }

    private static void FixupComplexType(HashSet<NdrComplexTypeReference> fixup_set, NdrComplexTypeReference complex_type, UserDefinedTypeInformation udt)
    {
        if (!fixup_set.Add(complex_type))
            return;

        // Fixup the name to remove compiler generated characters.
        complex_type.Name = CodeGenUtils.MakeIdentifier(udt.Name);
        if (complex_type is NdrUnionTypeReference union)
        {
            FixupUnionType(fixup_set, union, udt);
        }
        else if (complex_type is NdrBaseStructureTypeReference str)
        {
            FixupStructureType(fixup_set, str, udt);
        }
    }

    private static void FixupStructureNames(List<NdrProcedureDefinition> procs,
        ISymbolResolver symbol_resolver, NdrParserFlags parser_flags)
    {
        if (!parser_flags.HasFlagSet(NdrParserFlags.ResolveStructureNames) || symbol_resolver is not ISymbolTypeResolver type_resolver)
            return;

        var complex_types = new Dictionary<NdrComplexTypeReference, UserDefinedTypeInformation>();

        foreach (var proc in procs)
        {
            if (type_resolver.GetTypeForSymbolByAddress(proc.DispatchFunction) is not FunctionTypeInformation func_type)
                continue;

            if (func_type.Parameters.Count != proc.Params.Count)
                continue;

            for (int i = 0; i < func_type.Parameters.Count; ++i)
            {
                proc.Params[i].Name = func_type.Parameters[i].Name;
                UpdateComplexTypes(complex_types, func_type.Parameters[i].ParameterType, proc.Params[i].Type);
            }

            if (proc.ReturnValue != null && func_type.ReturnType != null)
            {
                UpdateComplexTypes(complex_types, func_type.ReturnType, proc.ReturnValue.Type);
            }
        }

        HashSet<NdrComplexTypeReference> fixup_set = new();
        foreach (var pair in complex_types)
        {
            FixupComplexType(fixup_set, pair.Key, pair.Value);
        }
    }

    private static MidlSyntaxInfoDce ReadDceProcs(IMemoryReader reader, MIDL_SERVER_INFO server_info, 
        IntPtr fmt_str_ofs, IntPtr proc_str, int start_offset, int dispatch_count, ISymbolResolver symbol_resolver, 
        IList<string> names, NdrParserFlags parser_flags, IntPtr base_address, NdrTypeCache type_cache)
    {
        IntPtr[] dispatch_funcs = server_info.GetDispatchTable(reader, dispatch_count);
        MIDL_STUB_DESC stub_desc = server_info.GetStubDesc(reader);
        IntPtr type_desc = stub_desc.pFormatTypes;
        NDR_EXPR_DESC expr_desc = stub_desc.GetExprDesc(reader);
        type_cache ??= new();
        Dictionary<int, NdrUnionArms> union_arms_cache = new();
        List<NdrProcedureDefinition> procs = new();
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
                        stub_desc, proc_str + fmt_ofs, type_desc, expr_desc, dispatch_funcs[i],
                        base_address, name, parser_flags, union_arms_cache));
                }
            }
        }

        FixupStructureNames(procs, symbol_resolver, parser_flags);

        return new MidlSyntaxInfoDce(procs, type_cache);
    }

    private static MidlSyntaxInfoNdr64 ReadNdr64Procs(IMemoryReader reader, MIDL_SERVER_INFO server_info,
        IntPtr fmt_str_ofs, int start_offset, int dispatch_count, ISymbolResolver symbol_resolver,
        IList<string> names, NdrParserFlags parser_flags, IntPtr base_address, Ndr64TypeCache type_cache)
    {
        type_cache ??= new();
        Ndr64ParseContext context = new() { Reader = reader, Cache = type_cache };
        IntPtr[] dispatch_funcs = server_info.GetDispatchTable(reader, dispatch_count);
        List<Ndr64ProcedureDefinition> procs = new();
        var format_info = reader.ReadArray<IntPtr>(fmt_str_ofs, dispatch_count);
        for (int i = start_offset; i < dispatch_count; ++i)
        {
            // Not implemented methods are set to -1.
            if (format_info[i] == new IntPtr(-1))
                continue;
            string name = null;
            if (names != null)
            {
                name = names[i - start_offset];
            }

            procs.Add(new Ndr64ProcedureDefinition(context, format_info[i], symbol_resolver,
                dispatch_funcs[i], base_address, name, i, parser_flags));
        }

        return new MidlSyntaxInfoNdr64(procs, type_cache);
    }

    private static IEnumerable<MidlSyntaxInfo> ReadProcs(IMemoryReader reader, MIDL_SERVER_INFO server_info, int start_offset,
        int dispatch_count, ISymbolResolver symbol_resolver, IList<string> names, NdrParserFlags parser_flags,
        IntPtr base_address, NdrTypeCache type_cache, Ndr64TypeCache type_cache_64)
    {
        List<MidlSyntaxInfo> ret = new();
        if (server_info.GetTransferSyntax(reader).SyntaxGUID != NdrNativeUtils.DCE_TransferSyntax)
        {
            MIDL_SYNTAX_INFO[] syntax_infos = server_info.GetSyntaxInfo(reader);
            foreach (var info in syntax_infos)
            {
                RpcSyntaxIdentifier transfer_syntax = new(info.TransferSyntax);
                if (transfer_syntax == RpcSyntaxIdentifier.DCETransferSyntax)
                {
                    ret.Add(ReadDceProcs(reader, server_info, info.FmtStringOffset, info.ProcString,
                        start_offset, dispatch_count, symbol_resolver, names, parser_flags, base_address, type_cache));
                }
                else if (transfer_syntax == RpcSyntaxIdentifier.NDR64TransferSyntax && !parser_flags.HasFlagSet(NdrParserFlags.IgnoreNdr64))
                {
                    if (info.FmtStringOffset != IntPtr.Zero)
                    {
                        ret.Add(ReadNdr64Procs(reader, server_info, info.FmtStringOffset, start_offset, dispatch_count, symbol_resolver,
                            names, parser_flags, base_address, type_cache_64));
                    }
                }
            }
        }
        else
        {
            ret.Add(ReadDceProcs(reader, server_info, server_info.FmtStringOffset, server_info.ProcString,
                start_offset, dispatch_count, symbol_resolver, names, parser_flags, base_address, type_cache));
        }

        if (ret.Count == 0)
        {
            throw new NdrParserException("No RPC NDR available.");
        }

        return ret.AsReadOnly();
    }

    private IEnumerable<NdrComplexTypeReference> ReadTypes(IntPtr midl_type_pickling_info_ptr, IntPtr midl_stub_desc_ptr, bool deref_stub_desc, Func<IMemoryReader, IntPtr, IEnumerable<int>> get_offsets)
    {
        if (midl_type_pickling_info_ptr == IntPtr.Zero)
        {
            throw new ArgumentException("Must specify a MIDL_TYPE_PICKLING_INFO pointer");
        }

        if (midl_stub_desc_ptr == IntPtr.Zero)
        {
            throw new ArgumentException($"Must specify a {(deref_stub_desc ? "MIDL_STUBLESS_PROXY_INFO" : "MIDL_STUB_DESC")} pointer");
        }

        if (deref_stub_desc)
        {
            midl_stub_desc_ptr = _reader.ReadIntPtr(midl_stub_desc_ptr);
        }

        var pickle_info = _reader.ReadStruct<MIDL_TYPE_PICKLING_INFO>(midl_type_pickling_info_ptr);
        if (pickle_info.Version != 0x33205054)
        {
            throw new ArgumentException($"Unsupported picking type version {pickle_info.Version:X}");
        }

        NdrInterpreterOptFlags2 flags = 0;
        if (pickle_info.Flags.HasFlag(MidlTypePicklingInfoFlags.NewCorrDesc))
            flags |= NdrInterpreterOptFlags2.HasNewCorrDesc;
        if (pickle_info.Flags.HasFlag(MidlTypePicklingInfoFlags.HasRangeOnConformance))
            flags |= NdrInterpreterOptFlags2.HasRangeOnConformance;
        MIDL_STUB_DESC stub_desc = _reader.ReadStruct<MIDL_STUB_DESC>(midl_stub_desc_ptr);
        NdrTypeCache type_cache = new();
        Dictionary<int, NdrUnionArms> union_arms_cache = new();
        NdrParseContext context = new(type_cache, null, stub_desc, stub_desc.pFormatTypes, stub_desc.GetExprDesc(_reader),
            flags, _reader, NdrParserFlags.IgnoreUserMarshal, union_arms_cache);
        foreach (var i in get_offsets(_reader, stub_desc.pFormatTypes))
        {
            NdrBaseTypeReference.Read(context, i);
        }
        type_cache.FixupLateBoundTypes();
        return type_cache.ComplexTypes.ToList().AsReadOnly();
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void GetProxyDllInfo(out IntPtr pInfo, out IntPtr pId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int DllGetClassObject(ref Guid clsid, ref Guid riid, out IntPtr ppv);

    private IList<MidlSyntaxInfo> ReadProcs(Guid base_iid, CInterfaceStubHeader stub, NdrTypeCache type_cache)
    {
        int start_ofs = 3;
        if (base_iid == NdrNativeUtils.IID_IDispatch)
        {
            start_ofs = 7;
        }
        else if (base_iid == NdrNativeUtils.IID_IInspectable)
        {
            start_ofs = 6;
        }

        return ReadProcs(_reader, _reader.ReadStruct<MIDL_SERVER_INFO>(stub.pServerInfo),
            start_ofs, stub.DispatchTableCount, _symbol_resolver, null, _parser_flags, IntPtr.Zero, type_cache, null).ToList();
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

            IntPtr pInfo = RTMarshal.ReadIntPtr(psfactory, 2 * IntPtr.Size);
            // TODO: Should add better checks here, 
            // for example VTable should be in COMBASE and the pointer should be in the
            // server DLL's rdata section. But this is probably good enough for now.
            using var module = SafeLoadLibraryHandle.GetModuleHandle(pInfo, false);
            if (!module.IsSuccess || lib.DangerousGetHandle() != module.Result.DangerousGetHandle())
            {
                return IntPtr.Zero;
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
                RTMarshal.Release(psfactory);
            }
        }
    }

    private NdrComProxy InitFromProxyFileInfo(ProxyFileInfo proxy_file_info, HashSet<Guid> iid_set)
    {
        string[] names = proxy_file_info.GetNames(_reader);
        CInterfaceStubHeader[] stubs = proxy_file_info.GetStubs(_reader);
        Guid[] base_iids = proxy_file_info.GetBaseIids(_reader);
        List<NdrComProxyInterface> interfaces = new();
        NdrTypeCache type_cache = new();
        for (int i = 0; i < names.Length; ++i)
        {
            Guid iid = stubs[i].GetIid(_reader);
            if (iid_set.Count == 0 || iid_set.Contains(iid))
            {
                interfaces.Add(new NdrComProxyInterface(names[i], iid,
                    base_iids[i], stubs[i].DispatchTableCount, ReadProcs(base_iids[i], stubs[i], type_cache)));
            }
        }
        return interfaces.Count > 0 ? new NdrComProxy(interfaces, type_cache) : null;
    }

    private bool InitFromProxyFileInfoArray(IntPtr proxy_file_info_array, IList<NdrComProxy> proxies, HashSet<Guid> iid_set)
    {
        foreach (var file_info in _reader.EnumeratePointerList<ProxyFileInfo>(proxy_file_info_array))
        {
            var proxy = InitFromProxyFileInfo(file_info, iid_set);
            if (proxy is not null)
            {
                proxies.Add(proxy);
            }
        }

        return true;
    }

    private bool InitFromFile(string path, Guid clsid, IList<NdrComProxy> proxies, IEnumerable<Guid> iids)
    {
        HashSet<Guid> iid_set = new(iids ?? Array.Empty<Guid>());
        using SafeLoadLibraryHandle lib = SafeLoadLibraryHandle.LoadLibrary(path);
        _symbol_resolver?.LoadModule(path, lib.DangerousGetHandle());
        IntPtr pInfo = FindProxyDllInfo(lib, clsid);
        if (pInfo == IntPtr.Zero)
        {
            return false;
        }

        return InitFromProxyFileInfoArray(pInfo, proxies, iid_set);
    }

    private static ISymbolResolver CheckSymbolResolver(NtProcess process, ISymbolResolver symbol_resolver)
    {
        int pid = process == null ? NtProcess.Current.ProcessId : process.ProcessId;
        if (symbol_resolver is DbgHelpSymbolResolver dbghelp_resolver)
        {
            if (dbghelp_resolver.Process.ProcessId != pid)
            {
                throw new ArgumentException("Symbol resolver must be for the same process as the passed process");
            }
        }
        return symbol_resolver;
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

    private static IMemoryReader CreateReader(NtProcess process)
    {
        if (process == null || process.ProcessId == NtProcess.Current.ProcessId)
        {
            return new CurrentProcessMemoryReader();
        }
        else
        {
            return MemoryUtils.CreateMemoryReader(process);
        }
    }

    private static IEnumerable<NdrComplexTypeReference> ReadPicklingComplexTypes(NdrParserFlags parser_flags, NtProcess process, IntPtr midl_type_pickling_info, IntPtr midl_stub_desc, bool deref_stub_desc, Func<IMemoryReader, IntPtr, IEnumerable<int>> get_offsets)
    {
        NdrParser parser = new(process, null, parser_flags);
        return RunWithAccessCatch(() => parser.ReadTypes(midl_type_pickling_info, midl_stub_desc, deref_stub_desc, get_offsets));
    }

    private static IEnumerable<int> GetPicklingTableOffsets(IMemoryReader reader, IntPtr type_pickling_offset_table, IEnumerable<int> type_index)
    {
        var table = reader.ReadIntPtr(type_pickling_offset_table);
        return type_index.Select(i => reader.ReadInt32(table + i * 4));
    }
    #endregion

    #region Internal Members
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="reader">Memory reader to parse from.</param>
    /// <param name="symbol_resolver">Specify a symbol resolver to use for looking up symbols.</param>
    /// <param name="parser_flags">Flags which affect the parsing operation.</param>
    internal NdrParser(IMemoryReader reader, ISymbolResolver symbol_resolver, NdrParserFlags parser_flags)
    {
        _reader = reader;
        _symbol_resolver = symbol_resolver;
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
        : this(CreateReader(process), CheckSymbolResolver(process, symbol_resolver), parser_flags)
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
    public NdrComProxy ReadFromProxyFileInfo(IntPtr proxy_file_info)
    {
        NdrComProxy ret = RunWithAccessCatch(() => InitFromProxyFileInfo(_reader.ReadStruct<ProxyFileInfo>(proxy_file_info), new HashSet<Guid>()));
        if (ret is null)
        {
            throw new NdrParserException("Can't find proxy information in server DLL");
        }

        return ret;
    }

    /// <summary>
    /// Read COM proxy information from an array of pointers to ProxyFileInfo structures.
    /// </summary>
    /// <param name="proxy_file_info_array">The address of an array of pointers to ProxyFileInfo structures. The last pointer should be NULL.</param>
    /// <returns>The list of parsed proxy definitions.</returns>
    public IEnumerable<NdrComProxy> ReadFromProxyFileInfoArray(IntPtr proxy_file_info_array)
    {
        List<NdrComProxy> proxies = new();
        if (!RunWithAccessCatch(() => InitFromProxyFileInfoArray(proxy_file_info_array, proxies, new HashSet<Guid>())))
        {
            throw new NdrParserException("Can't find proxy information in server DLL");
        }

        return proxies.AsReadOnly();
    }

    /// <summary>
    /// Read COM proxy information from a file.
    /// </summary>
    /// <param name="path">The path to the DLL containing the proxy.</param>
    /// <param name="clsid">Optional CLSID for the proxy class.</param>
    /// <param name="iids">List of IIDs to parse.</param>
    /// <returns>The parsed proxy definitions.</returns>
    public IEnumerable<NdrComProxy> ReadFromComProxyFile(string path, Guid clsid = default, IEnumerable<Guid> iids = null)
    {
        if (!_reader.InProcess)
        {
            throw new NdrParserException("Can't parse COM proxy information from a file out of process.");
        }

        List<NdrComProxy> proxies = new();
        if (!RunWithAccessCatch(() => InitFromFile(path, clsid, proxies, iids)))
        {
            throw new NdrParserException("Can't find proxy information in server DLL");
        }

        return proxies.AsReadOnly();
    }

    /// <summary>
    /// Parse NDR content from an RPC_SERVER_INTERFACE structure in memory.
    /// </summary>
    /// <param name="server_interface">Pointer to the RPC_SERVER_INTERFACE.</param>
    /// <returns>The parsed NDR content.</returns>
    public RpcServerInterface ReadFromRpcServerInterface(IntPtr server_interface)
    {
        return ReadFromRpcServerInterface(server_interface, IntPtr.Zero);
    }

    /// <summary>
    /// Parse NDR content from an RPC_SERVER_INTERFACE structure in memory.
    /// </summary>
    /// <param name="server_interface">Pointer to the RPC_SERVER_INTERFACE.</param>
    /// <param name="base_address">Base address of the library which contains the interface.</param>
    /// <returns>The parsed NDR content.</returns>
    public RpcServerInterface ReadFromRpcServerInterface(IntPtr server_interface, IntPtr base_address)
    {
        return RunWithAccessCatch(() => ReadRpcServerInterface(_reader,
            _reader.ReadStruct<RPC_SERVER_INTERFACE>(server_interface), _symbol_resolver,
            _parser_flags, base_address));
    }

    /// <summary>
    /// Parse NDR content from an RPC_SERVER_INTERFACE structure in memory.
    /// </summary>
    /// <param name="dll_path">The path to a DLL containing the RPC_SERVER_INTERFACE.</param>
    /// <param name="offset">Offset to the RPC_SERVER_INTERFACE from the base of the DLL.</param>
    /// <returns>The parsed NDR content.</returns>
    public RpcServerInterface ReadFromRpcServerInterface(string dll_path, int offset)
    {
        using var lib = SafeLoadLibraryHandle.LoadLibrary(dll_path, LoadLibraryFlags.DontResolveDllReferences);
        _symbol_resolver?.LoadModule(dll_path, lib.DangerousGetHandle());
        return ReadFromRpcServerInterface(lib.DangerousGetHandle() + offset);
    }

    /// <summary>
    /// Parse NDR procedures from an MIDL_SERVER_INFO structure in memory.
    /// </summary>
    /// <param name="server_info">Pointer to the MIDL_SERVER_INFO.</param>
    /// <param name="dispatch_count">Number of dispatch functions to parse.</param>
    /// <param name="start_offset">The start offset to parse from. This is used for COM where the first few proxy stubs are not implemented.</param>
    /// <param name="names">List of names for the valid procedures. Should either be null or a list equal in size to dispatch_count - start_offset.</param>
    /// <returns>The parsed NDR content.</returns>
    public IEnumerable<MidlSyntaxInfo> ReadFromMidlServerInfo(IntPtr server_info, int start_offset, int dispatch_count, IList<string> names)
    {
        if (names != null && names.Count != dispatch_count - start_offset)
        {
            throw new NdrParserException("List of names must be same size of the total methods to parse");
        }
        return RunWithAccessCatch(() => ReadProcs(_reader, _reader.ReadStruct<MIDL_SERVER_INFO>(server_info),
            start_offset, dispatch_count, _symbol_resolver, names, _parser_flags,
            IntPtr.Zero, null, null));
    }

    /// <summary>
    /// Parse NDR procedures from an MIDL_SERVER_INFO structure in memory.
    /// </summary>
    /// <param name="server_info">Pointer to the MIDL_SERVER_INFO.</param>
    /// <param name="dispatch_count">Number of dispatch functions to parse.</param>
    /// <param name="start_offset">The start offset to parse from. This is used for COM where the first few proxy stubs are not implemented.</param>
    /// <returns>The parsed NDR content.</returns>
    public IEnumerable<MidlSyntaxInfo> ReadFromMidlServerInfo(IntPtr server_info, int start_offset, int dispatch_count)
    {
        return RunWithAccessCatch(() => ReadProcs(_reader, _reader.ReadStruct<MIDL_SERVER_INFO>(server_info),
            start_offset, dispatch_count, _symbol_resolver, null, _parser_flags, IntPtr.Zero, null, null));
    }

    #endregion

    #region Static Methods

    /// <summary>
    /// Parse NDR complex type information from a pickling structure. Used to extract explicit Encode/Decode method information.
    /// </summary>
    /// <param name="process">The process to read from.</param>
    /// <param name="midl_type_pickling_info">Pointer to the MIDL_TYPE_PICKLING_INFO structure.</param>
    /// <param name="midl_stub_desc">The pointer to the MIDL_STUB_DESC structure.</param>
    /// <param name="type_offsets">Pointers to the the format string to the start of the types.</param>
    /// <param name="parser_flags">Specify additional parser flags.</param>
    /// <returns>The list of complex types.</returns>
    /// <remarks>This function is used to extract type information for calls to NdrMesTypeDecode2. MIDL_TYPE_PICKLING_INFO is the second parameter,
    /// MIDL_STUB_DESC is the third, the Type Offsets is the fourth parameter.</remarks>
    public static IEnumerable<NdrComplexTypeReference> ReadPicklingComplexTypes(NtProcess process, IntPtr midl_type_pickling_info, IntPtr midl_stub_desc, IntPtr[] type_offsets, NdrParserFlags parser_flags)
    {
        if (type_offsets.Length == 0)
        {
            return new NdrComplexTypeReference[0];
        }

        return ReadPicklingComplexTypes(parser_flags, process, midl_type_pickling_info, midl_stub_desc, false, (r, f) => type_offsets.Select(p => (int)(p.ToInt64() - f.ToInt64())));
    }

    /// <summary>
    /// Parse NDR complex type information from a pickling structure. Used to extract explicit Encode/Decode method information.
    /// </summary>
    /// <param name="process">The process to read from.</param>
    /// <param name="midl_type_pickling_info">Pointer to the MIDL_TYPE_PICKLING_INFO structure.</param>
    /// <param name="midl_stubless_proxy">The pointer to the MIDL_STUBLESS_PROXY_INFO structure.</param>
    /// <param name="type_pickling_offset_table">Pointer to the type pickling offset table.</param>
    /// <param name="type_index">Index into type_pickling_offset_table array.</param>
    /// <param name="parser_flags">Specify additional parser flags.</param>
    /// <returns>The list of complex types.</returns>
    /// <remarks>This function is used to extract type information for calls to NdrMesTypeDecode3. MIDL_TYPE_PICKLING_INFO is the second parameter,
    /// MIDL_STUBLESS_PROXY_INFO is the third, the type pickling offset table is the fourth and the type index is the fifth.</remarks>
    public static IEnumerable<NdrComplexTypeReference> ReadPicklingComplexTypes(NtProcess process, IntPtr midl_type_pickling_info,
        IntPtr midl_stubless_proxy, IntPtr type_pickling_offset_table, int[] type_index, NdrParserFlags parser_flags)
    {
        if (type_index.Length == 0)
        {
            return new NdrComplexTypeReference[0];
        }

        return ReadPicklingComplexTypes(parser_flags, process, midl_type_pickling_info, midl_stubless_proxy, true, (r, f) => GetPicklingTableOffsets(r, type_pickling_offset_table, type_index));
    }

    /// <summary>
    /// Parse NDR complex type information from a pickling structure. Used to extract explicit Encode/Decode method information.
    /// </summary>
    /// <param name="process">The process to read from.</param>
    /// <param name="midl_type_pickling_info">Pointer to the MIDL_TYPE_PICKLING_INFO structure.</param>
    /// <param name="midl_stub_desc">The pointer to the MIDL_STUB_DESC structure.</param>
    /// <param name="start_offsets">Offsets into the format string to the start of the types.</param>
    /// <param name="parser_flags">Specify additional parser flags.</param>
    /// <returns>The list of complex types.</returns>
    /// <remarks>This function is used to extract type information for calls to NdrMesTypeDecode2. MIDL_TYPE_PICKLING_INFO is the second parameter,
    /// MIDL_STUB_DESC is the third (minus the offset).</remarks>
    public static IEnumerable<NdrComplexTypeReference> ReadPicklingComplexTypes(NtProcess process,
        IntPtr midl_type_pickling_info, IntPtr midl_stub_desc, int[] start_offsets, NdrParserFlags parser_flags)
    {
        if (start_offsets.Length == 0)
        {
            return new NdrComplexTypeReference[0];
        }

        return ReadPicklingComplexTypes(parser_flags, process, midl_type_pickling_info, midl_stub_desc, false, (r, f) => start_offsets);
    }

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
    public static IEnumerable<NdrComplexTypeReference> ReadPicklingComplexTypes(NtProcess process, IntPtr midl_type_pickling_info,
        IntPtr midl_stub_desc, params int[] start_offsets)
    {
        return ReadPicklingComplexTypes(process, midl_type_pickling_info, midl_stub_desc, start_offsets, NdrParserFlags.IgnoreUserMarshal);
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
