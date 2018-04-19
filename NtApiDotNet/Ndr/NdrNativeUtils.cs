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

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Ndr
{
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

        internal static Guid ReadGuid(IMemoryReader reader, IntPtr p)
        {
            if (p == IntPtr.Zero)
            {
                return NdrInterfacePointerTypeReference.IID_IUnknown;
            }
            return new Guid(reader.ReadBytes(p, 16));
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
