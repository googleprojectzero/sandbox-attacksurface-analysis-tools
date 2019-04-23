//  Copyright 2019 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Ndr;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    internal enum LRPC_MESSAGE_TYPE
    {
        lmtRequest = 0,
        lmtBind = 1,
        lmtFault = 2,
        lmtResponse = 3,
        lmtCancel = 4,
        lmtReservedMessage = 5,     // LRPC_ADDRESS::HandleReservedMessageRequest
        lmtCallbackAck = 7,
        lmtCallbackNack = 8,
        lmtCallbackRequest = 9,
        lmtCallbackReply = 10,
        lmtCallbackFault = 11,
        lmtPipePull = 12,
        lmtPipeAck = 13,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LRPC_HEADER
    {
        public LRPC_MESSAGE_TYPE MessageType;
        public int Padding;

        public LRPC_HEADER(LRPC_MESSAGE_TYPE message_type)
        {
            MessageType = message_type;
            Padding = 0;
        }
    }

    [Flags]
    enum TransferSyntaxSetFlags
    {
        None = 0,
        UseDce = 1,
        UseNdr64 = 2,
        UseFakeNdr64 = 4
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LRPC_BIND_MESSAGE
    {
        public LRPC_HEADER Header;
        public int RpcStatus;
        public RPC_SYNTAX_IDENTIFIER Interface;
        public TransferSyntaxSetFlags TransferSyntaxSet;
        public short DceNdrSyntaxIdentifier;
        public short Ndr64SyntaxIdentifier;
        public short FakeNdr64SyntaxIdentifier;
        [MarshalAs(UnmanagedType.Bool)]
        public bool RegisterMultipleSyntax;
        [MarshalAs(UnmanagedType.Bool)]
        public bool UseFlowId;
        public long FlowId;
        public int ContextId;

        public LRPC_BIND_MESSAGE(Guid guid, Version interface_version) : this()
        {
            Header = new LRPC_HEADER(LRPC_MESSAGE_TYPE.lmtBind);
            Interface = new RPC_SYNTAX_IDENTIFIER(guid, (ushort)interface_version.Major, (ushort)interface_version.Minor);
            TransferSyntaxSet = TransferSyntaxSetFlags.UseDce;
        }
    }

    [Flags]
    internal enum LRPC_REQUEST_MESSAGE_FLAGS
    {
        None = 0,
        ObjectUuid = 1,
        PartOfFlow = 2,
        ViewPresent = 4,
        Cancel = 8,
        PipeRequest = 0x40,
        PipeLastChunk = 0x80,
        ViewNotSecure = 0x100,
    }

    // Total size is 0x48 for large request, 0x40 for small request.
    [StructLayout(LayoutKind.Sequential)]
    internal struct LRPC_IMMEDIATE_REQUEST_MESSAGE
    {
        // 0
        public LRPC_HEADER Header;
        // 2 - 0x08
        public LRPC_REQUEST_MESSAGE_FLAGS Flags;
        // 3 - 0x0C
        public int CallId;
        // 4 - 0x10
        public int BindingId; // Interface number from binding.
        // 5 - 0x14
        public int ProcNum;
        // 6 - 0x18
        public int Unk18;
        // 7 - 0x1C
        public int Unk1C;
        // 8 - 0x20
        public int Unk20;
        // 9 - 0x24
        public int Unk24;
        // 10 - 0x28
        public int Unk28; // SequenceNumbers.PipeBufferNumber
        // 11 - 0x2C
        public int Unk2C;
        // 12 - 0x30
        public Guid ObjectUuid; // Needs ObjectUuid flag set.
    }

    // Total size is 0x48 for large request, 0x40 for small request.
    [StructLayout(LayoutKind.Sequential)]
    internal struct LRPC_LARGE_REQUEST_MESSAGE
    {
        // 0
        public LRPC_HEADER Header;
        // 2 - 0x08
        public LRPC_REQUEST_MESSAGE_FLAGS Flags;
        // 3 - 0x0C
        public int CallId;
        // 4 - 0x10
        public int BindingId; // Interface number from binding.
        // 5 - 0x14
        public int ProcNum;
        // 6 - 0x18
        public int Unk18;
        // 7 - 0x1C
        public int Unk1C;
        // 8 - 0x20
        public int Unk20;
        // 9 - 0x24
        public int Unk24;
        // 10 - 0x28
        public int Unk28; // SequenceNumbers.PipeBufferNumber
        // 11 - 0x2C
        public int Unk2C;
        // 12 - 0x30
        public Guid ObjectUuid; // Needs ObjectUuid flag set.
        // This is where LARGE_REQUEST starts, for IMMEDIATE_REQUEST this is the start of data.
        // 16 - 0x40
        public int LargeDataSize;
        // Probably padding for 8 byte alignment.
        // 17 - 0x44
        public int Padding;
    }

    [Flags]
    internal enum LRPC_RESPONSE_MESSAGE_FLAGS
    {
        None = 0,
        ViewPresent = 4,
    }

    // Total size is 0x48 for large request, 0x40 for small request.
    [StructLayout(LayoutKind.Sequential)]
    internal struct LRPC_LARGE_RESPONSE_MESSAGE
    {
        // 0
        public LRPC_HEADER Header;
        // 8
        public LRPC_RESPONSE_MESSAGE_FLAGS Flags;
        // C
        public int CallId;

        public int Unk10;
        public int Unk14;

        // 18
        public int LargeDataSize;
        // Probably padding for 8 byte alignment.
        // 1C
        public int Padding;
    }

    // Total size is 0x20 for large request, 0x18 for small request.
    // This structure is followed by the NDR encoded data (and 8 byte aligned).
    [StructLayout(LayoutKind.Sequential)]
    internal struct LRPC_IMMEDIATE_RESPONSE_MESSAGE
    {
        // 0
        public LRPC_HEADER Header;
        // 8
        public LRPC_RESPONSE_MESSAGE_FLAGS Flags;
        // C
        public int CallId;

        public int Unk10;
        public int Unk14;
    }

    [Flags]
    internal enum LRPC_FAULT_MESSAGE_FLAGS
    {
        None = 0,
        ExtendedErrorInfo = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LRPC_FAULT_MESSAGE
    {
        public LRPC_HEADER Header;
        public int RpcStatus;
        public LRPC_FAULT_MESSAGE_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("ExtendedErrorInfo")]
    internal struct LRPC_FAULT_MESSAGE_EXTENDED
    {
        public LRPC_HEADER Header;
        public int RpcStatus;
        public LRPC_FAULT_MESSAGE_FLAGS Flags;
        // Trailing data is the Extended Error Info, which is NDR encoded.
        public long ExtendedErrorInfo;
    }
}
