//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Utilities.Reflection;

namespace NtApiDotNet.Win32.Security.Buffers
{
#pragma warning disable 1591
    /// <summary>
    /// Security buffer type.
    /// </summary>
    public enum SecurityBufferType : uint
    {
        [SDKName("SECBUFFER_EMPTY")]
        Empty = 0,
        [SDKName("SECBUFFER_DATA")]
        Data = 1,
        [SDKName("SECBUFFER_TOKEN")]
        Token = 2,
        [SDKName("SECBUFFER_PKG_PARAMS")]
        PkgParams = 3,
        [SDKName("SECBUFFER_MISSING")]
        Missing = 4,
        [SDKName("SECBUFFER_EXTRA")]
        Extra = 5,
        [SDKName("SECBUFFER_STREAM_TRAILER")]
        StreamTrailer = 6,
        [SDKName("SECBUFFER_STREAM_HEADER")]
        StreamHeader = 7,
        [SDKName("SECBUFFER_NEGOTIATION_INFO")]
        NegotiationInfo = 8,
        [SDKName("SECBUFFER_PADDING")]
        Padding = 9,
        [SDKName("SECBUFFER_STREAM")]
        Stream = 10,
        [SDKName("SECBUFFER_MECHLIST")]
        Mechlist = 11,
        [SDKName("SECBUFFER_MECLIST_SIGNATURE")]
        MechlistSignature = 12,
        [SDKName("SECBUFFER_TARGET")]
        Target = 13,
        [SDKName("SECBUFFER_CHANNEL_BINDINGS")]
        ChannelBindings = 14,
        [SDKName("SECBUFFER_CHANGE_PASS_RESPONSE")]
        ChangePassResponse = 15,
        [SDKName("SECBUFFER_TARGET_HOST")]
        TargetHost = 16,
        [SDKName("SECBUFFER_ALERT")]
        Alert = 17,
        [SDKName("SECBUFFER_APPLICATION_PROTOCOLS")]
        ApplicationProtocols = 18,
        [SDKName("SECBUFFER_SRTP_PROTECTION_PROFILES")]
        SRTPProtectionProfiles = 19,
        [SDKName("SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER")]
        SRTPMasterKeyIdentifier = 20,
        [SDKName("SECBUFFER_TOKEN_BINDING")]
        TokenBinding = 21,
        [SDKName("SECBUFFER_PRESHARED_KEY")]
        PresharedKey = 22,
        [SDKName("SECBUFFER_PRESHARED_KEY_IDENTITY")]
        PresharedKeyIdentity = 23,
        [SDKName("SECBUFFER_DTLS_MTU")]
        DTLAMtu = 24,
        // Mask to remove the upper flags.
        [SDKName("SECBUFFER_ATTRMASK")]
        Mask = 0x0FFFFFFF,
        [SDKName("SECBUFFER_READONLY")]
        ReadOnlyWithChecksum = 0x10000000,
        [SDKName("SECBUFFER_READONLY_WITH_CHECKSUM")]
        ReadOnly = 0x80000000,
    }
}
