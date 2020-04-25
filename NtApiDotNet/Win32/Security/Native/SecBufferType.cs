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

namespace NtApiDotNet.Win32.Security.Native
{
#pragma warning disable 1591
    /// <summary>
    /// Security buffer type.
    /// </summary>
    internal enum SecBufferType
    {
        Empty = 0,
        Data = 1,
        Token = 2,
        PkgParams = 3,
        Missing = 4,
        Extra = 5,
        StreamTrailer = 6,
        StreamHeader = 7,
        NegotiationInfo = 8,
        Padding = 9,
        Stream = 10,
        Mechlist = 11,
        MechlistSignature = 12,
        Target = 13,
        ChannelBindings = 14,
        ChangePassResponse = 15,
        TargetHost = 16,
        Alert = 17,
        ApplicationProtocols = 18,
        SRTPProtectionProfiles = 19,
        SRTPMasterKeyIdentifier = 20,
        TokenBinding = 21,
        PresharedKey = 22,
        PresharedKeyIdentity = 23,
        DTLAMtu = 24,
    }
}
