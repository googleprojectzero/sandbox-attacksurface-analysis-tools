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
    /// Guids for pre-defined callouts.
    /// </summary>
    public static class FirewallCalloutGuids
    {
        // 5132900d-5e84-4b5f-80e4-01741e81ff10
        public static Guid
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
           FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V4 = new Guid(
           0x5132900d,
           0x5e84,
           0x4b5f,
           0x80, 0xe4, 0x01, 0x74, 0x1e, 0x81, 0xff, 0x10
        );

        // 49d3ac92-2a6c-4dcf-955f-1c3be009dd99
        public static Guid
           FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V6 = new Guid(
           0x49d3ac92,
           0x2a6c,
           0x4dcf,
           0x95, 0x5f, 0x1c, 0x3b, 0xe0, 0x09, 0xdd, 0x99
        );

        // 4b46bf0a-4523-4e57-aa38-a87987c910d9
        public static Guid
           FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V4 = new Guid(
           0x4b46bf0a,
           0x4523,
           0x4e57,
           0xaa, 0x38, 0xa8, 0x79, 0x87, 0xc9, 0x10, 0xd9
        );

        // 38d87722-ad83-4f11-a91f-df0fb077225b
        public static Guid
           FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V6 = new Guid(
           0x38d87722,
           0xad83,
           0x4f11,
           0xa9, 0x1f, 0xdf, 0x0f, 0xb0, 0x77, 0x22, 0x5b
        );

        // 191a8a46-0bf8-46cf-b045-4b45dfa6a324
        public static Guid
           FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_V4 = new Guid(
           0x191a8a46,
           0x0bf8,
           0x46cf,
           0xb0, 0x45, 0x4b, 0x45, 0xdf, 0xa6, 0xa3, 0x24
        );

        // 80c342e3-1e53-4d6f-9b44-03df5aeee154
        public static Guid
           FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_V6 = new Guid(
           0x80c342e3,
           0x1e53,
           0x4d6f,
           0x9b, 0x44, 0x03, 0xdf, 0x5a, 0xee, 0xe1, 0x54
        );

        // 70a4196c-835b-4fb0-98e8-075f4d977d46
        public static Guid
           FWPM_CALLOUT_IPSEC_OUTBOUND_TUNNEL_V4 = new Guid(
           0x70a4196c,
           0x835b,
           0x4fb0,
           0x98, 0xe8, 0x07, 0x5f, 0x4d, 0x97, 0x7d, 0x46
        );

        // f1835363-a6a5-4e62-b180-23db789d8da6
        public static Guid
           FWPM_CALLOUT_IPSEC_OUTBOUND_TUNNEL_V6 = new Guid(
           0xf1835363,
           0xa6a5,
           0x4e62,
           0xb1, 0x80, 0x23, 0xdb, 0x78, 0x9d, 0x8d, 0xa6
        );

        // 28829633-c4f0-4e66-873f-844db2a899c7
        public static Guid
           FWPM_CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V4 = new Guid(
           0x28829633,
           0xc4f0,
           0x4e66,
           0x87, 0x3f, 0x84, 0x4d, 0xb2, 0xa8, 0x99, 0xc7
        );

        // af50bec2-c686-429a-884d-b74443e7b0b4
        public static Guid
           FWPM_CALLOUT_IPSEC_FORWARD_INBOUND_TUNNEL_V6 = new Guid(
           0xaf50bec2,
           0xc686,
           0x429a,
           0x88, 0x4d, 0xb7, 0x44, 0x43, 0xe7, 0xb0, 0xb4
        );

        // fb532136-15cb-440b-937c-1717ca320c40
        public static Guid
           FWPM_CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V4 = new Guid(
           0xfb532136,
           0x15cb,
           0x440b,
           0x93, 0x7c, 0x17, 0x17, 0xca, 0x32, 0x0c, 0x40
        );

        // dae640cc-e021-4bee-9eb6-a48b275c8c1d
        public static Guid
           FWPM_CALLOUT_IPSEC_FORWARD_OUTBOUND_TUNNEL_V6 = new Guid(
           0xdae640cc,
           0xe021,
           0x4bee,
           0x9e, 0xb6, 0xa4, 0x8b, 0x27, 0x5c, 0x8c, 0x1d
        );

        // 7dff309b-ba7d-4aba-91aa-ae5c6640c944
        public static Guid
           FWPM_CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V4 = new Guid(
           0x7dff309b,
           0xba7d,
           0x4aba,
           0x91, 0xaa, 0xae, 0x5c, 0x66, 0x40, 0xc9, 0x44
        );

        // a9a0d6d9-c58c-474e-8aeb-3cfe99d6d53d
        public static Guid
           FWPM_CALLOUT_IPSEC_INBOUND_INITIATE_SECURE_V6 = new Guid(
           0xa9a0d6d9,
           0xc58c,
           0x474e,
           0x8a, 0xeb, 0x3c, 0xfe, 0x99, 0xd6, 0xd5, 0x3d
        );

        // 3df6e7de-fd20-48f2-9f26-f854444cba79
        public static Guid
           FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V4 = new Guid(
           0x3df6e7de,
           0xfd20,
           0x48f2,
           0x9f, 0x26, 0xf8, 0x54, 0x44, 0x4c, 0xba, 0x79
        );

        // a1e392d3-72ac-47bb-87a7-0122c69434ab
        public static Guid
           FWPM_CALLOUT_IPSEC_INBOUND_TUNNEL_ALE_ACCEPT_V6 = new Guid(
           0xa1e392d3,
           0x72ac,
           0x47bb,
           0x87, 0xa7, 0x01, 0x22, 0xc6, 0x94, 0x34, 0xab
        );

        // 6ac141fc-f75d-4203-b9c8-48e6149c2712
        public static Guid
           FWPM_CALLOUT_IPSEC_ALE_CONNECT_V4 = new Guid(
           0x6ac141fc,
           0xf75d,
           0x4203,
           0xb9, 0xc8, 0x48, 0xe6, 0x14, 0x9c, 0x27, 0x12
        );

        // 4c0dda05-e31f-4666-90b0-b3dfad34129a
        public static Guid
           FWPM_CALLOUT_IPSEC_ALE_CONNECT_V6 = new Guid(
           0x4c0dda05,
           0xe31f,
           0x4666,
           0x90, 0xb0, 0xb3, 0xdf, 0xad, 0x34, 0x12, 0x9a
        );

        // 6d08a342-db9e-4fbe-9ed2-57374ce89f79
        public static Guid
           FWPM_CALLOUT_IPSEC_DOSP_FORWARD_V6 = new Guid(
           0x6d08a342,
           0xdb9e,
           0x4fbe,
           0x9e, 0xd2, 0x57, 0x37, 0x4c, 0xe8, 0x9f, 0x79
        );

        // 2fcb56ec-cd37-4b4f-b108-62c2b1850a0c
        public static Guid
           FWPM_CALLOUT_IPSEC_DOSP_FORWARD_V4 = new Guid(
           0x2fcb56ec,
           0xcd37,
           0x4b4f,
           0xb1, 0x08, 0x62, 0xc2, 0xb1, 0x85, 0x0a, 0x0c
        );

        // eda08606-2494-4d78-89bc-67837c03b969
        public static Guid
           FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V4_SILENT_DROP = new Guid(
           0xeda08606,
           0x2494,
           0x4d78,
           0x89, 0xbc, 0x67, 0x83, 0x7c, 0x03, 0xb9, 0x69
);

        // 8693cc74-a075-4156-b476-9286eece814e
        public static Guid
           FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V6_SILENT_DROP = new Guid(
           0x8693cc74,
           0xa075,
           0x4156,
           0xb4, 0x76, 0x92, 0x86, 0xee, 0xce, 0x81, 0x4e);

        // f3e10ab3-2c25-4279-ac36-c30fc181bec4
        public static Guid
           FWPM_CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V4 = new Guid(
           0xf3e10ab3,
           0x2c25,
           0x4279,
           0xac, 0x36, 0xc3, 0x0f, 0xc1, 0x81, 0xbe, 0xc4
        );

        // 39e22085-a341-42fc-a279-aec94e689c56
        public static Guid
           FWPM_CALLOUT_TCP_CHIMNEY_CONNECT_LAYER_V6 = new Guid(
           0x39e22085,
           0xa341,
           0x42fc,
           0xa2, 0x79, 0xae, 0xc9, 0x4e, 0x68, 0x9c, 0x56
        );

        // e183ecb2-3a7f-4b54-8ad9-76050ed880ca
        public static Guid
           FWPM_CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V4 = new Guid(
           0xe183ecb2,
           0x3a7f,
           0x4b54,
           0x8a, 0xd9, 0x76, 0x05, 0x0e, 0xd8, 0x80, 0xca
        );

        // 0378cf41-bf98-4603-81f2-7f12586079f6
        public static Guid
           FWPM_CALLOUT_TCP_CHIMNEY_ACCEPT_LAYER_V6 = new Guid(
           0x0378cf41,
           0xbf98,
           0x4603,
           0x81, 0xf2, 0x7f, 0x12, 0x58, 0x60, 0x79, 0xf6
        );

        // bc582280-1677-41e9-94ab-c2fcb15c2eeb
        public static Guid
           FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V4 = new Guid(
           0xbc582280,
           0x1677,
           0x41e9,
           0x94, 0xab, 0xc2, 0xfc, 0xb1, 0x5c, 0x2e, 0xeb
        );

        // 98e5373c-b884-490f-b65f-2f6a4a575195
        public static Guid
           FWPM_CALLOUT_SET_OPTIONS_AUTH_CONNECT_LAYER_V6 = new Guid(
           0x98e5373c,
           0xb884,
           0x490f,
           0xb6, 0x5f, 0x2f, 0x6a, 0x4a, 0x57, 0x51, 0x95
        );

        // 2d55f008-0c01-4f92-b26e-a08a94569b8d
        public static Guid
           FWPM_CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V4 = new Guid(
           0x2d55f008,
           0x0c01,
           0x4f92,
           0xb2, 0x6e, 0xa0, 0x8a, 0x94, 0x56, 0x9b, 0x8d
        );

        // 63018537-f281-4dc4-83d3-8dec18b7ade2
        public static Guid
           FWPM_CALLOUT_SET_OPTIONS_AUTH_RECV_ACCEPT_LAYER_V6 = new Guid(
           0x63018537,
           0xf281,
           0x4dc4,
           0x83, 0xd3, 0x8d, 0xec, 0x18, 0xb7, 0xad, 0xe2
        );

        // 288B524D-0566-4e19-B612-8F441A2E5949
        public static Guid
           FWPM_CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V4 = new Guid(
           0x288b524d,
           0x566,
           0x4e19,
           0xb6, 0x12, 0x8f, 0x44, 0x1a, 0x2e, 0x59, 0x49
        );

        // 00B84B92-2B5E-4b71-AB0E-AACA43E387E6
        public static Guid
           FWPM_CALLOUT_RESERVED_AUTH_CONNECT_LAYER_V6 = new Guid(
           0xb84b92,
           0x2b5e,
           0x4b71,
           0xab, 0xe, 0xaa, 0xca, 0x43, 0xe3, 0x87, 0xe6
        );

        // 31b95392-066e-42a2-b7db-92f8acdd56f9
        public static Guid
           FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_RESOURCE_ASSIGNMENT_V6 = new Guid(
           0x31b95392,
           0x066e,
           0x42a2,
           0xb7, 0xdb, 0x92, 0xf8, 0xac, 0xdd, 0x56, 0xf9
        );

        // 079b1010-f1c5-4fcd-ae05-da41107abd0b
        public static Guid
            FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_RESOURCE_ASSIGNMENT_V4 = new Guid(
            0x079b1010,
            0xf1c5,
            0x4fcd,
            0xae, 0x05, 0xda, 0x41, 0x10, 0x7a, 0xbd, 0x0b
        );

        // 81a434e7-f60c-4378-bab8-c625a30f0197
        public static Guid
           FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_LISTEN_V6 = new Guid(
           0x81a434e7,
           0xf60c,
           0x4378,
           0xba, 0xb8, 0xc6, 0x25, 0xa3, 0x0f, 0x01, 0x97
        );

        // 33486ab5-6d5e-4e65-a00b-a7afed0ba9a1
        public static Guid
            FWPM_CALLOUT_EDGE_TRAVERSAL_ALE_LISTEN_V4 = new Guid(
            0x33486ab5,
            0x6d5e,
            0x4e65,
            0xa0, 0x0b, 0xa7, 0xaf, 0xed, 0x0b, 0xa9, 0xa1
        );

        // 215a0b39-4b7e-4eda-8ce4-179679df6224
        public static Guid
           FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V4 = new Guid(
           0x215a0b39,
           0x4b7e,
           0x4eda,
           0x8c, 0xe4, 0x17, 0x96, 0x79, 0xdf, 0x62, 0x24
        );

        // 838b37a1-5c12-4d34-8b38-078728b2d25c
        public static Guid
           FWPM_CALLOUT_TCP_TEMPLATES_CONNECT_LAYER_V6 = new Guid(
           0x838b37a1,
           0x5c12,
           0x4d34,
           0x8b, 0x38, 0x07, 0x87, 0x28, 0xb2, 0xd2, 0x5c
        );

        // 2f23f5d0-40c4-4c41-a254-46d8dba8957c
        public static Guid
           FWPM_CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V4 = new Guid(
           0x2f23f5d0,
           0x40c4,
           0x4c41,
           0xa2, 0x54, 0x46, 0xd8, 0xdb, 0xa8, 0x95, 0x7c
        );

        // b25152f0-991c-4f53-bbe7-d24b45fe632c
        public static Guid
           FWPM_CALLOUT_TCP_TEMPLATES_ACCEPT_LAYER_V6 = new Guid(
           0xb25152f0,
           0x991c,
           0x4f53,
           0xbb, 0xe7, 0xd2, 0x4b, 0x45, 0xfe, 0x63, 0x2c
        );

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
