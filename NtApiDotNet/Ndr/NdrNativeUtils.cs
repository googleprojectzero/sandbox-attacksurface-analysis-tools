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

using Microsoft.Win32.SafeHandles;
using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Ndr
{
    internal sealed class SafeRpcBindingHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcBindingFree(ref IntPtr Binding);

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcBindingToStringBinding(
            IntPtr Binding,
            out SafeRpcStringHandle StringBinding
        );

        public SafeRpcBindingHandle() : base(true)
        {
        }

        public SafeRpcBindingHandle(IntPtr handle, bool owns_handle) : base(owns_handle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return RpcBindingFree(ref handle) == 0;
        }

        public static SafeRpcBindingHandle Create(string string_binding)
        {
            int status = NdrNativeUtils.RpcBindingFromStringBinding(string_binding, out SafeRpcBindingHandle binding);
            if (status != 0)
            {
                throw new SafeWin32Exception(status);
            }
            return binding;
        }

        public override string ToString()
        {
            if (!IsInvalid && !IsClosed)
            {
                if (RpcBindingToStringBinding(handle, out SafeRpcStringHandle str) == 0)
                {
                    using (str)
                    {
                        return str.ToString();
                    }
                }
            }
            return string.Empty;
        }

        public static SafeRpcBindingHandle Null => new SafeRpcBindingHandle(IntPtr.Zero, false);
    }

    internal sealed class SafeRpcStringHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcStringFree(
            ref IntPtr String
        );

        public SafeRpcStringHandle() : base(true)
        {
        }

        public SafeRpcStringHandle(IntPtr handle, bool owns_handle) : base(owns_handle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return RpcStringFree(ref handle) == 0;
        }

        public override string ToString()
        {
            if (!IsInvalid && !IsClosed)
            {
                return Marshal.PtrToStringUni(handle);
            }
            return string.Empty;
        }
    }

    internal sealed class SafeRpcInquiryHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcMgmtEpEltInqDone(
          ref IntPtr InquiryContext
        );

        public SafeRpcInquiryHandle() : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return RpcMgmtEpEltInqDone(ref handle) == 0;
        }
    }

    internal enum RpcEndPointVersionOption
    {
        All = 1,
        Compatible = 2,
        Exact = 3,
        MajorOnly = 4,
        Upto = 5
    }

    internal enum RpcEndpointInquiryFlag
    {
        All = 0,
        Interface = 1,
        Object = 2,
        Both = 3,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class UUID
    {
        public Guid Uuid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class RPC_IF_ID
    {
        public Guid Uuid;
        public ushort VersMajor;
        public ushort VersMinor;
    }

    internal class CrackedBindingString
    {
        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        static extern int RpcStringBindingParse(
              string StringBinding,
              out SafeRpcStringHandle ObjUuid,
              out SafeRpcStringHandle Protseq,
              out SafeRpcStringHandle NetworkAddr,
              out SafeRpcStringHandle Endpoint,
              out SafeRpcStringHandle NetworkOptions
            );

        public string ObjUuid { get; }
        public string Protseq { get; }
        public string NetworkAddr { get; }
        public string Endpoint { get; }
        public string NetworkOptions { get; }

        public CrackedBindingString(string string_binding)
        {
            SafeRpcStringHandle objuuid = null;
            SafeRpcStringHandle protseq = null;
            SafeRpcStringHandle endpoint = null;
            SafeRpcStringHandle networkaddr = null;
            SafeRpcStringHandle networkoptions = null;

            try
            {
                int status = RpcStringBindingParse(string_binding, out objuuid, out protseq, out networkaddr, out endpoint, out networkoptions);
                if (status == 0)
                {
                    ObjUuid = objuuid.ToString();
                    Protseq = protseq.ToString();
                    Endpoint = endpoint.ToString();
                    NetworkAddr = networkaddr.ToString();
                    NetworkOptions = networkoptions.ToString();
                }
                else
                {
                    ObjUuid = string.Empty;
                    Protseq = string.Empty;
                    Endpoint = string.Empty;
                    NetworkAddr = string.Empty;
                    NetworkOptions = string.Empty;
                }
            }
            finally
            {
                objuuid?.Dispose();
                protseq?.Dispose();
                endpoint?.Dispose();
                networkaddr?.Dispose();
                networkoptions?.Dispose();
            }
        }
    }

    internal static class NdrNativeUtils
    {
        internal static byte[] ReadAll(this BinaryReader reader, int length)
        {
            byte[] ret = reader.ReadBytes(length);
            if (ret.Length != length)
            {
                throw new EndOfStreamException();
            }
            return ret;
        }

        internal static Guid ReadComGuid(this IMemoryReader reader, IntPtr p)
        {
            if (p == IntPtr.Zero)
            {
                return IID_IUnknown;
            }
            return new Guid(reader.ReadBytes(p, 16));
        }

        internal static T[] EnumeratePointerList<T>(this IMemoryReader reader, IntPtr p, Func<IntPtr, T> load_type)
        {
            List<T> ret = new List<T>();

            if (p == IntPtr.Zero)
            {
                return new T[0];
            }

            IntPtr curr = p;
            IntPtr value = IntPtr.Zero;
            while ((value = reader.ReadIntPtr(curr)) != IntPtr.Zero)
            {
                ret.Add(load_type(value));
                curr += reader.PointerSize;
            }
            return ret.ToArray();
        }

        internal static T[] EnumeratePointerList<T>(this IMemoryReader reader, IntPtr p) where T : struct
        {
            return EnumeratePointerList(reader, p, i => reader.ReadStruct<T>(i));
        }

        internal static T[] ReadPointerArray<T>(this IMemoryReader reader, IntPtr p, int count, Func<IntPtr, T> load_type)
        {
            T[] ret = new T[count];
            if (p == IntPtr.Zero)
            {
                return ret;
            }

            for (int i = 0; i < count; ++i)
            {
                IntPtr curr = reader.ReadIntPtr(p + i * reader.PointerSize);
                if (curr == IntPtr.Zero)
                {
                    ret[i] = default(T);
                }
                else
                {
                    ret[i] = load_type(curr);
                }
            }
            return ret;
        }

        internal static T[] ReadPointerArray<T>(this IMemoryReader reader, IntPtr p, int count) where T : struct
        {
            return ReadPointerArray(reader, p, count, i => reader.ReadStruct<T>(i));
        }

        internal static RPC_VERSION ToRpcVersion(this Version version)
        {
            return new RPC_VERSION() { MajorVersion = (ushort)version.Major, MinorVersion = (ushort)version.Minor };
        }

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcBindingFromStringBinding([MarshalAs(UnmanagedType.LPTStr)] string StringBinding, out SafeRpcBindingHandle Binding);

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcEpResolveBinding(SafeRpcBindingHandle Binding, ref RPC_SERVER_INTERFACE IfSpec);

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcMgmtEpEltInqBegin(
            SafeRpcBindingHandle EpBinding,
            RpcEndpointInquiryFlag InquiryType,
            RPC_IF_ID IfId,
            RpcEndPointVersionOption VersOption,
            UUID ObjectUuid,
            out SafeRpcInquiryHandle InquiryContext
        );

        [DllImport("rpcrt4.dll", CharSet = CharSet.Unicode)]
        internal static extern int RpcMgmtEpEltInqNext(
          SafeRpcInquiryHandle InquiryContext,
          [Out] RPC_IF_ID IfId,
          out SafeRpcBindingHandle Binding,
          [Out] UUID ObjectUuid,
          out SafeRpcStringHandle Annotation
        );

        internal static readonly Guid IID_IUnknown = new Guid("00000000-0000-0000-C000-000000000046");
        internal static readonly Guid IID_IDispatch = new Guid("00020400-0000-0000-C000-000000000046");
        internal static readonly Guid IID_IPSFactoryBuffer = new Guid("D5F569D0-593B-101A-B569-08002B2DBF7A");
        internal static readonly Guid DCE_TransferSyntax = new Guid("8A885D04-1CEB-11C9-9FE8-08002B104860");
        internal static readonly Guid NDR64_TransferSyntax = new Guid("71710533-BEBA-4937-8319-B5DBEF9CCC36");
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ProxyFileInfo32 : IConvertToNative<ProxyFileInfo>
    {
        public IntPtr32 pProxyVtblList;
        public IntPtr32 pStubVtblList;
        public IntPtr32 pNamesArray;
        public IntPtr32 pDelegatedIIDs;
        public IntPtr32 pIIDLookupRtn;
        public ushort TableSize;
        public ushort TableVersion;

        public ProxyFileInfo Convert()
        {
            ProxyFileInfo ret = new ProxyFileInfo();
            ret.pProxyVtblList = pProxyVtblList.Convert();
            ret.pStubVtblList = pStubVtblList.Convert();
            ret.pNamesArray = pNamesArray.Convert();
            ret.pDelegatedIIDs = pDelegatedIIDs.Convert();
            ret.pIIDLookupRtn = pIIDLookupRtn.Convert();
            ret.TableSize = TableSize;
            ret.TableVersion = TableVersion;
            return ret;
        }
    }

    [StructLayout(LayoutKind.Sequential), CrossBitnessType(typeof(ProxyFileInfo32))]
    struct ProxyFileInfo
    {
        public IntPtr pProxyVtblList;
        public IntPtr pStubVtblList;
        public IntPtr pNamesArray;
        public IntPtr pDelegatedIIDs;
        public IntPtr pIIDLookupRtn;
        public ushort TableSize;
        public ushort TableVersion;

        public string[] GetNames(IMemoryReader reader)
        {
            return reader.ReadPointerArray(pNamesArray, TableSize, i => reader.ReadAnsiStringZ(i));
        }

        public Guid[] GetBaseIids(IMemoryReader reader)
        {
            return reader.ReadPointerArray(pDelegatedIIDs, TableSize, i => reader.ReadComGuid(i));
        }

        public CInterfaceStubHeader[] GetStubs(IMemoryReader reader)
        {
            return reader.ReadPointerArray<CInterfaceStubHeader>(pStubVtblList, TableSize);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CInterfaceStubHeader32 : IConvertToNative<CInterfaceStubHeader>
    {
        public IntPtr32 piid;
        public IntPtr32 pServerInfo;
        public int DispatchTableCount;
        public IntPtr32 pDispatchTable;

        public CInterfaceStubHeader Convert()
        {
            CInterfaceStubHeader ret = new CInterfaceStubHeader();
            ret.piid = piid.Convert();
            ret.pServerInfo = pServerInfo.Convert();
            ret.DispatchTableCount = DispatchTableCount;
            ret.pDispatchTable = pDispatchTable.Convert();
            return ret;
        }
    }

    [StructLayout(LayoutKind.Sequential), CrossBitnessType(typeof(CInterfaceStubHeader32))]
    struct CInterfaceStubHeader
    {
        public IntPtr piid;
        public IntPtr pServerInfo;
        public int DispatchTableCount;
        public IntPtr pDispatchTable;

        public Guid GetIid(IMemoryReader reader)
        {
            return reader.ReadComGuid(piid);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_STUB_DESC32 : IConvertToNative<MIDL_STUB_DESC>
    {
        public IntPtr32 RpcInterfaceInformation;
        public IntPtr32 pfnAllocate;
        public IntPtr32 pfnFree;
        public IntPtr32 pGenericBindingInfo;
        public IntPtr32 apfnNdrRundownRoutines;
        public IntPtr32 aGenericBindingRoutinePairs;
        public IntPtr32 apfnExprEval;
        public IntPtr32 aXmitQuintuple;
        public IntPtr32 pFormatTypes;
        public int fCheckBounds;
        public int Version;
        public IntPtr32 pMallocFreeStruct;
        public int MIDLVersion;
        public IntPtr32 CommFaultOffsets;
        public IntPtr32 aUserMarshalQuadruple;
        public IntPtr32 NotifyRoutineTable;
        public IntPtr32 mFlags;
        public IntPtr32 CsRoutineTables;
        public IntPtr32 ProxyServerInfo;
        public IntPtr32 pExprInfo;
        public MIDL_STUB_DESC Convert()
        {
            MIDL_STUB_DESC ret = new MIDL_STUB_DESC();
            ret.RpcInterfaceInformation = RpcInterfaceInformation.Convert();
            ret.pfnAllocate = pfnAllocate.Convert();
            ret.pfnFree = pfnFree.Convert();
            ret.pGenericBindingInfo = pGenericBindingInfo.Convert();
            ret.apfnNdrRundownRoutines = apfnNdrRundownRoutines.Convert();
            ret.aGenericBindingRoutinePairs = aGenericBindingRoutinePairs.Convert();
            ret.apfnExprEval = apfnExprEval.Convert();
            ret.aXmitQuintuple = aXmitQuintuple.Convert();
            ret.pFormatTypes = pFormatTypes.Convert();
            ret.fCheckBounds = fCheckBounds;
            ret.Version = Version;
            ret.pMallocFreeStruct = pMallocFreeStruct.Convert();
            ret.MIDLVersion = MIDLVersion;
            ret.CommFaultOffsets = CommFaultOffsets.Convert();
            ret.aUserMarshalQuadruple = aUserMarshalQuadruple.Convert();
            ret.NotifyRoutineTable = NotifyRoutineTable.Convert();
            ret.mFlags = mFlags.Convert();
            ret.CsRoutineTables = CsRoutineTables.Convert();
            ret.ProxyServerInfo = ProxyServerInfo.Convert();
            ret.pExprInfo = pExprInfo.Convert();
            return ret;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_SERVER_INFO32 : IConvertToNative<MIDL_SERVER_INFO>
    {
        public IntPtr32 pStubDesc;
        public IntPtr32 DispatchTable;
        public IntPtr32 ProcString;
        public IntPtr32 FmtStringOffset;
        public IntPtr32 ThunkTable;
        public IntPtr32 pTransferSyntax;
        public IntPtr32 nCount;
        public IntPtr32 pSyntaxInfo;
        public MIDL_SERVER_INFO Convert()
        {
            MIDL_SERVER_INFO ret = new MIDL_SERVER_INFO();
            ret.pStubDesc = pStubDesc.Convert();
            ret.DispatchTable = DispatchTable.Convert();
            ret.ProcString = ProcString.Convert();
            ret.FmtStringOffset = FmtStringOffset.Convert();
            ret.ThunkTable = ThunkTable.Convert();
            ret.pTransferSyntax = pTransferSyntax.Convert();
            ret.nCount = nCount.Convert();
            ret.pSyntaxInfo = pSyntaxInfo.Convert();
            return ret;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_DISPATCH_TABLE32 : IConvertToNative<RPC_DISPATCH_TABLE>
    {
        public int DispatchTableCount;
        public IntPtr32 DispatchTable;
        public IntPtr32 Reserved;
        public RPC_DISPATCH_TABLE Convert()
        {
            RPC_DISPATCH_TABLE ret = new RPC_DISPATCH_TABLE();
            ret.DispatchTableCount = DispatchTableCount;
            ret.DispatchTable = DispatchTable.Convert();
            ret.Reserved = Reserved.Convert();
            return ret;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_SERVER_INTERFACE32 : IConvertToNative<RPC_SERVER_INTERFACE>
    {
        public int Length;
        public RPC_SYNTAX_IDENTIFIER InterfaceId;
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr32 DispatchTable;
        public int RpcProtseqEndpointCount;
        public IntPtr32 RpcProtseqEndpoint;
        public IntPtr32 DefaultManagerEpv;
        public IntPtr32 InterpreterInfo;
        public int Flags;
        public RPC_SERVER_INTERFACE Convert()
        {
            RPC_SERVER_INTERFACE ret = new RPC_SERVER_INTERFACE();
            ret.Length = Length;
            ret.InterfaceId = InterfaceId;
            ret.TransferSyntax = TransferSyntax;
            ret.DispatchTable = DispatchTable.Convert();
            ret.RpcProtseqEndpointCount = RpcProtseqEndpointCount;
            ret.RpcProtseqEndpoint = RpcProtseqEndpoint.Convert();
            ret.DefaultManagerEpv = DefaultManagerEpv.Convert();
            ret.InterpreterInfo = InterpreterInfo.Convert();
            ret.Flags = Flags;
            return ret;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_SYNTAX_INFO32 : IConvertToNative<MIDL_SYNTAX_INFO>
    {
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr32 DispatchTable; // RPC_DISPATCH_TABLE
        public IntPtr32 ProcString; // PFORMAT_STRING 
        public IntPtr32 FmtStringOffset; // const unsigned short* 
        public IntPtr32 TypeString; // PFORMAT_STRING 
        public IntPtr32 aUserMarshalQuadruple; // const void* 
        public IntPtr32 pMethodProperties; // const MIDL_INTERFACE_METHOD_PROPERTIES* 
        public IntPtr32 pReserved2;

        public MIDL_SYNTAX_INFO Convert()
        {
            MIDL_SYNTAX_INFO ret = new MIDL_SYNTAX_INFO();
            ret.TransferSyntax = TransferSyntax;
            ret.DispatchTable = DispatchTable.Convert();
            ret.ProcString = ProcString.Convert();
            ret.FmtStringOffset = ProcString.Convert();
            ret.TypeString = TypeString.Convert();
            ret.aUserMarshalQuadruple = aUserMarshalQuadruple.Convert();
            ret.pMethodProperties = pMethodProperties.Convert();
            ret.pReserved2 = pReserved2.Convert();
            return ret;
        }
    }

    [StructLayout(LayoutKind.Sequential), CrossBitnessType(typeof(MIDL_SYNTAX_INFO32))]
    internal struct MIDL_SYNTAX_INFO
    {
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr DispatchTable; // RPC_DISPATCH_TABLE
        public IntPtr ProcString; // PFORMAT_STRING 
        public IntPtr FmtStringOffset; // const unsigned short* 
        public IntPtr TypeString; // PFORMAT_STRING 
        public IntPtr aUserMarshalQuadruple; // const void* 
        public IntPtr pMethodProperties; // const MIDL_INTERFACE_METHOD_PROPERTIES* 
        public IntPtr pReserved2;
    }

    [StructLayout(LayoutKind.Sequential), CrossBitnessType(typeof(MIDL_STUB_DESC32))]
    internal struct MIDL_STUB_DESC
    {
        public IntPtr RpcInterfaceInformation;
        public IntPtr pfnAllocate;
        public IntPtr pfnFree;
        public IntPtr pGenericBindingInfo;
        public IntPtr apfnNdrRundownRoutines;
        public IntPtr aGenericBindingRoutinePairs;
        public IntPtr apfnExprEval;
        public IntPtr aXmitQuintuple;
        public IntPtr pFormatTypes;
        public int fCheckBounds;
        /* Ndr library version. */
        public int Version;
        public IntPtr pMallocFreeStruct;
        public int MIDLVersion;
        public IntPtr CommFaultOffsets;
        // New fields for version 3.0+
        public IntPtr aUserMarshalQuadruple;
        // Notify routines - added for NT5, MIDL 5.0
        public IntPtr NotifyRoutineTable;
        public IntPtr mFlags;
        // International support routines - added for 64bit post NT5
        public IntPtr CsRoutineTables;
        public IntPtr ProxyServerInfo;
        public IntPtr pExprInfo;
    }

    [StructLayout(LayoutKind.Sequential), CrossBitnessType(typeof(MIDL_SERVER_INFO32))]
    internal struct MIDL_SERVER_INFO
    {
        public IntPtr pStubDesc;
        public IntPtr DispatchTable;
        public IntPtr ProcString;
        public IntPtr FmtStringOffset;
        public IntPtr ThunkTable;
        public IntPtr pTransferSyntax;
        public IntPtr nCount;
        public IntPtr pSyntaxInfo;

        public MIDL_STUB_DESC GetStubDesc(IMemoryReader reader)
        {
            if (pStubDesc == IntPtr.Zero)
            {
                return new MIDL_STUB_DESC();
            }
            return reader.ReadStruct<MIDL_STUB_DESC>(pStubDesc);
        }

        public IntPtr[] GetDispatchTable(IMemoryReader reader, int dispatch_count)
        {
            if (DispatchTable == IntPtr.Zero)
            {
                return new IntPtr[dispatch_count];
            }
            return reader.ReadArray<IntPtr>(DispatchTable, dispatch_count);
        }

        public RPC_SYNTAX_IDENTIFIER GetTransferSyntax(IMemoryReader reader)
        {
            if (pTransferSyntax == IntPtr.Zero)
            {
                return new RPC_SYNTAX_IDENTIFIER() { SyntaxGUID = NdrNativeUtils.DCE_TransferSyntax };
            }
            return reader.ReadStruct<RPC_SYNTAX_IDENTIFIER>(pTransferSyntax);
        }

        public MIDL_SYNTAX_INFO[] GetSyntaxInfo(IMemoryReader reader)
        {
            if (nCount == IntPtr.Zero || pSyntaxInfo == IntPtr.Zero)
            {
                return new MIDL_SYNTAX_INFO[0];
            }
            return reader.ReadArray<MIDL_SYNTAX_INFO>(pSyntaxInfo, nCount.ToInt32());
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_VERSION
    {
        public ushort MajorVersion;
        public ushort MinorVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_SYNTAX_IDENTIFIER
    {
        public Guid SyntaxGUID;
        public RPC_VERSION SyntaxVersion;
    }

    [StructLayout(LayoutKind.Sequential), CrossBitnessType(typeof(RPC_DISPATCH_TABLE32))]
    internal struct RPC_DISPATCH_TABLE
    {
        public int DispatchTableCount;
        public IntPtr DispatchTable; // RPC_DISPATCH_FUNCTION*
        public IntPtr Reserved;

        public IntPtr[] GetDispatchTable(IMemoryReader reader)
        {
            return reader.ReadArray<IntPtr>(DispatchTable, DispatchTableCount);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_PROTSEQ_ENDPOINT32 : IConvertToNative<RPC_PROTSEQ_ENDPOINT>
    {
        public IntPtr32 RpcProtocolSequence;
        public IntPtr32 Endpoint;

        public RPC_PROTSEQ_ENDPOINT Convert()
        {
            RPC_PROTSEQ_ENDPOINT ret = new RPC_PROTSEQ_ENDPOINT();
            ret.RpcProtocolSequence = RpcProtocolSequence.Convert();
            ret.Endpoint = Endpoint.Convert();
            return ret;
        }
    }

    [StructLayout(LayoutKind.Sequential), CrossBitnessType(typeof(RPC_PROTSEQ_ENDPOINT32))]
    internal struct RPC_PROTSEQ_ENDPOINT
    {
        public IntPtr RpcProtocolSequence;
        public IntPtr Endpoint;

        public string GetRpcProtocolSequence(IMemoryReader reader)
        {
            if (RpcProtocolSequence == IntPtr.Zero)
            {
                return string.Empty;
            }
            return reader.ReadAnsiStringZ(RpcProtocolSequence);
        }

        public string GetEndpoint(IMemoryReader reader)
        {
            if (Endpoint == IntPtr.Zero)
            {
                return string.Empty;
            }
            return reader.ReadAnsiStringZ(Endpoint);
        }
    }

    [StructLayout(LayoutKind.Sequential), CrossBitnessType(typeof(RPC_SERVER_INTERFACE32))]
    internal struct RPC_SERVER_INTERFACE
    {
        public int Length;
        public RPC_SYNTAX_IDENTIFIER InterfaceId;
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr DispatchTable; // PRPC_DISPATCH_TABLE
        public int RpcProtseqEndpointCount;
        public IntPtr RpcProtseqEndpoint; // PRPC_PROTSEQ_ENDPOINT 
        public IntPtr DefaultManagerEpv;
        public IntPtr InterpreterInfo;    // MIDL_SERVER_INFO
        public int Flags;

        public RPC_DISPATCH_TABLE GetDispatchTable(IMemoryReader reader)
        {
            if (DispatchTable == IntPtr.Zero)
            {
                return new RPC_DISPATCH_TABLE();
            }

            return reader.ReadStruct<RPC_DISPATCH_TABLE>(DispatchTable);
        }

        public MIDL_SERVER_INFO GetServerInfo(IMemoryReader reader)
        {
            if (InterpreterInfo == IntPtr.Zero)
            {
                return new MIDL_SERVER_INFO();
            }
            return reader.ReadStruct<MIDL_SERVER_INFO>(InterpreterInfo);
        }

        public RPC_PROTSEQ_ENDPOINT[] GetProtSeq(IMemoryReader reader)
        {
            if (RpcProtseqEndpoint == IntPtr.Zero || RpcProtseqEndpointCount == 0)
            {
                return new RPC_PROTSEQ_ENDPOINT[0];
            }
            return reader.ReadArray<RPC_PROTSEQ_ENDPOINT>(RpcProtseqEndpoint, RpcProtseqEndpointCount);
        }
    }

    [Flags]
    enum NdrInterpreterFlags : byte
    {
        FullPtrUsed = 0x01,
        RpcSsAllocUsed = 0x02,
        ObjectProc = 0x04,
        HasRpcFlags = 0x08,
        IgnoreObjectException = 0x10,
        HasCommOrFault = 0x20,
        UseNewInitRoutines = 0x40,
    }

    [StructLayout(LayoutKind.Sequential)]
    struct NdrProcHeaderExts
    {
        public byte Size;
        public NdrInterpreterOptFlags2 Flags2;
        public ushort ClientCorrHint;
        public ushort ServerCorrHint;
        public ushort NotifyIndex;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct NdrProcHeaderExts64
    {
        public byte Size;
        public NdrInterpreterOptFlags2 Flags2;
        public ushort ClientCorrHint;
        public ushort ServerCorrHint;
        public ushort NotifyIndex;
        public ushort FloatArgMask;
    }

    class SafeBufferWrapper : SafeBuffer
    {
        public SafeBufferWrapper(IntPtr buffer)
            : base(false)
        {
            this.Initialize(int.MaxValue);
            handle = buffer;
        }

        protected override bool ReleaseHandle()
        {
            return true;
        }
    }
}
