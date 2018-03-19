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

        internal static Guid ReadGuid(IntPtr p)
        {
            if (p == IntPtr.Zero)
            {
                return NdrInterfacePointerTypeReference.IID_IUnknown;
            }
            byte[] guid = new byte[16];
            Marshal.Copy(p, guid, 0, 16);
            return new Guid(guid);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
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

    [StructLayout(LayoutKind.Sequential)]
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

        public MIDL_STUB_DESC GetStubDesc()
        {
            if (pStubDesc == IntPtr.Zero)
            {
                return new MIDL_STUB_DESC();
            }
            return (MIDL_STUB_DESC)Marshal.PtrToStructure(pStubDesc, typeof(MIDL_STUB_DESC));
        }

        public IntPtr[] GetDispatchTable(int dispatch_count)
        {
            if (DispatchTable == IntPtr.Zero)
            {
                return new IntPtr[dispatch_count];
            }
            IntPtr[] table = new IntPtr[dispatch_count];
            Marshal.Copy(DispatchTable, table, 0, table.Length);
            return table;
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

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_DISPATCH_TABLE
    {
        public int DispatchTableCount;
        public IntPtr DispatchTable; // RPC_DISPATCH_FUNCTION*
        public IntPtr Reserved;

        public IntPtr[] GetDispatchTable()
        {
            IntPtr[] table = new IntPtr[DispatchTableCount];
            Marshal.Copy(DispatchTable, table, 0, table.Length);
            return table;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
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

        public RPC_DISPATCH_TABLE GetDispatchTable()
        {
            if (DispatchTable == IntPtr.Zero)
            {
                return new RPC_DISPATCH_TABLE();
            }

            return (RPC_DISPATCH_TABLE)Marshal.PtrToStructure(DispatchTable, typeof(RPC_DISPATCH_TABLE));
        }

        public MIDL_SERVER_INFO GetServerInfo()
        {
            if (InterpreterInfo == IntPtr.Zero)
            {
                return new MIDL_SERVER_INFO();
            }
            return (MIDL_SERVER_INFO)Marshal.PtrToStructure(InterpreterInfo, typeof(MIDL_SERVER_INFO));
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
