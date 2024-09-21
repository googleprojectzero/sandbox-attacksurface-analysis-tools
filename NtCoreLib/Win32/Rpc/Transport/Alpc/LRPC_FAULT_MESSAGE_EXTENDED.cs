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

using NtCoreLib.Utilities.Data;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Rpc.Transport.Alpc;

[StructLayout(LayoutKind.Sequential), DataStart("ExtendedErrorInfo")]
internal struct LRPC_FAULT_MESSAGE_EXTENDED
{
    public LRPC_HEADER Header;
    public int RpcStatus;
    public LRPC_FAULT_MESSAGE_FLAGS Flags;
    // Trailing data is the Extended Error Info, which is NDR encoded.
    public long ExtendedErrorInfo;
}
