//  Copyright 2021 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Security.Native
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct AUTHZ_RPC_INIT_INFO_CLIENT
    {
        public const ushort AUTHZ_RPC_INIT_INFO_CLIENT_VERSION_V1 = 1;

        public ushort version;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ObjectUuid;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ProtSeq;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string NetworkAddr;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Endpoint;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Options;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ServerSpn;
    }
}
