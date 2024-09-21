//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Win32;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Net.Sockets
{
    internal static class SocketNativeMethods
    {
        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int WSAQuerySocketSecurity(
            IntPtr Socket,
            SafeBuffer SecurityQueryTemplate,
            int SecurityQueryTemplateLen,
            SafeBuffer SecurityQueryInfo,
            ref int SecurityQueryInfoLen,
            IntPtr Overlapped,
            IntPtr CompletionRoutine
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int WSASetSocketSecurity(
            IntPtr Socket,
            SafeBuffer SecuritySettings,
            int SecuritySettingsLen,
            IntPtr Overlapped,
            IntPtr CompletionRoutine
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int WSAImpersonateSocketPeer(
          IntPtr Socket,
          [Out] byte[] PeerAddr,
          int PeerAddrLen
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int WSASetSocketPeerTargetName(
            IntPtr Socket,
            SafeBuffer PeerTargetName,
            int PeerTargetNameLen,
            IntPtr Overlapped,
            IntPtr CompletionRoutine
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int WSADeleteSocketPeerTargetName(
            IntPtr Socket,
            byte[] PeerAddr,
            int PeerAddrLen,
            IntPtr Overlapped,
            IntPtr CompletionRoutine
        );

        [DllImport("Ws2_32.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error WSAGetLastError();
    }
}
