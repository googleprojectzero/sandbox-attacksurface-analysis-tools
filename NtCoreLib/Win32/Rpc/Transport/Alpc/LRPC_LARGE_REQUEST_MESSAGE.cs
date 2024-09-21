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

using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Rpc.Transport.Alpc;

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
