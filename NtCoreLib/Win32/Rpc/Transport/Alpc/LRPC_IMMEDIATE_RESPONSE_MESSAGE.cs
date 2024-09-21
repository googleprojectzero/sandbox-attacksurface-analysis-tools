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

using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Rpc.Transport.Alpc;

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
