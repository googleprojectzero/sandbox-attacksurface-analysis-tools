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

namespace NtApiDotNet.Win32.Rpc.EndpointMapper
{
    internal enum RpcTowerId
    {
        None = 0,
        DNetNSP = 0x04, // ncacn_dnet_dsp
        Tcp = 0x07,     // ncacn_ip_tcp
        Udp = 0x08,     // ncacn_ip_udp
        NetbiosTcp = 0x09, // ncacn_nb_tcp
        Spx = 0x0C,         // ncacn_spx
        NetbiosIpx = 0xD,   // ncacn_np_ipx
        Ipx = 0x0E,         // ncacg_ipx
        NamedPipe = 0xF,    // ncacn_np
        LRPC = 0x10,        // ncalrpc
        NetBIOS = 0x13,     // ncacn_nb_nb
        AppleTalkDSP = 0x16,// ncacn_at_dsp
        AppleTalkDDP = 0x17,// ncacg_at_ddp
        BanyanVinesSPP = 0x1A, // ncacn_vns_spp
        MessageQueue = 0x1D,   // ncadg_mq
        Http = 0x1F,           // ncacn_http
        Container = 0x21,      // ncacn_hvsocket
    }
}
