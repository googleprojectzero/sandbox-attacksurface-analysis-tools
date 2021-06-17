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

using System;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Guids for pre-defined firewall sub-layers.
    /// </summary>
    public static class FirewallSubLayerGuids
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        // 758c84f4-fb48-4de9-9aeb-3ed9551ab1fd
        public static Guid FWPM_SUBLAYER_RPC_AUDIT = new Guid(0x758c84f4, 0xfb48, 0x4de9, 0x9a, 0xeb, 0x3e, 0xd9, 0x55, 0x1a, 0xb1, 0xfd);
        // 83f299ed-9ff4-4967-aff4-c309f4dab827
        public static Guid FWPM_SUBLAYER_IPSEC_TUNNEL = new Guid(0x83f299ed, 0x9ff4, 0x4967, 0xaf, 0xf4, 0xc3, 0x09, 0xf4, 0xda, 0xb8, 0x27);
        // eebecc03-ced4-4380-819a-2734397b2b74
        public static Guid FWPM_SUBLAYER_UNIVERSAL = new Guid(0xeebecc03, 0xced4, 0x4380, 0x81, 0x9a, 0x27, 0x34, 0x39, 0x7b, 0x2b, 0x74);
        // 1b75c0ce-ff60-4711-a70f-b4958cc3b2d0
        public static Guid FWPM_SUBLAYER_LIPS = new Guid(0x1b75c0ce, 0xff60, 0x4711, 0xa7, 0x0f, 0xb4, 0x95, 0x8c, 0xc3, 0xb2, 0xd0);
        // 15a66e17-3f3c-4f7b-aa6c-812aa613dd82
        public static Guid FWPM_SUBLAYER_SECURE_SOCKET = new Guid(0x15a66e17, 0x3f3c, 0x4f7b, 0xaa, 0x6c, 0x81, 0x2a, 0xa6, 0x13, 0xdd, 0x82);
        // 337608b9-b7d5-4d5f-82f9-3618618bc058
        public static Guid FWPM_SUBLAYER_TCP_CHIMNEY_OFFLOAD = new Guid(0x337608b9, 0xb7d5, 0x4d5f, 0x82, 0xf9, 0x36, 0x18, 0x61, 0x8b, 0xc0, 0x58);
        // 877519e1-e6a9-41a5-81b4-8c4f118e4a60
        public static Guid FWPM_SUBLAYER_INSPECTION = new Guid(0x877519e1, 0xe6a9, 0x41a5, 0x81, 0xb4, 0x8c, 0x4f, 0x11, 0x8e, 0x4a, 0x60);
        // ba69dc66-5176-4979-9c89-26a7b46a8327
        public static Guid FWPM_SUBLAYER_TEREDO = new Guid(0xba69dc66, 0x5176, 0x4979, 0x9c, 0x89, 0x26, 0xa7, 0xb4, 0x6a, 0x83, 0x27);
        // a5082e73-8f71-4559-8a9a-101cea04ef87
        public static Guid FWPM_SUBLAYER_IPSEC_FORWARD_OUTBOUND_TUNNEL = new Guid(0xa5082e73, 0x8f71, 0x4559, 0x8a, 0x9a, 0x10, 0x1c, 0xea, 0x04, 0xef, 0x87);
        // e076d572-5d3d-48ef-802b-909eddb098bd
        public static Guid FWPM_SUBLAYER_IPSEC_DOSP = new Guid(0xe076d572, 0x5d3d, 0x48ef, 0x80, 0x2b, 0x90, 0x9e, 0xdd, 0xb0, 0x98, 0xbd);
        // 24421dcf-0ac5-4caa-9e14-50f6e3636af0
        public static Guid FWPM_SUBLAYER_TCP_TEMPLATES = new Guid(0x24421dcf, 0x0ac5, 0x4caa, 0x9e, 0x14, 0x50, 0xf6, 0xe3, 0x63, 0x6a, 0xf0);
        // 37a57701-5884-4964-92b8-3e704688b0ad
        public static Guid FWPM_SUBLAYER_IPSEC_SECURITY_REALM = new Guid(0x37a57701, 0x5884, 0x4964, 0x92, 0xb8, 0x3e, 0x70, 0x46, 0x88, 0xb0, 0xad);
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
