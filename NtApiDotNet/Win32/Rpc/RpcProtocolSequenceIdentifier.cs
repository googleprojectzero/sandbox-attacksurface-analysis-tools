//  Copyright 2022 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Rpc
{
    /// <summary>
    /// RPC defined IDs for protocol sequences.
    /// </summary>
    public enum RpcProtocolSequenceIdentifier
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        DNetNSP = 0x04,
        Tcp = 0x07,
        Udp = 0x08,
        NetbiosTcp = 0x09,
        Spx = 0x0C,
        NetbiosIpx = 0xD,
        Ipx = 0x0E,
        NamedPipe = 0xF,
        LRPC = 0x10,
        NetBIOS = 0x13,
        AppleTalkDSP = 0x16,
        AppleTalkDDP = 0x17,
        BanyanVinesSPP = 0x1A,
        MessageQueue = 0x1D,
        Http = 0x1F,
        Container = 0x21,
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
