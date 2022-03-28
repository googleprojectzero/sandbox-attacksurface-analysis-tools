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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Key usage for kernel encryption.
    /// </summary>
    public enum KerberosKeyUsage
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        AsReqPaEncTimestamp = 1,
        AsRepTgsRepTicket = 2,
        AsRepEncryptedPart = 3,
        TgsReqKdcReqBodySessionKey = 4,
        TgsReqKdcReqBodyAuthSubkey = 5,
        TgsReqPaTgsReqApReqChksum = 6,
        TgsReqPaTgsReqApReq = 7,
        TgsRepEncryptedPart = 8,
        TgsRepEncryptedPartAuthSubkey = 9,
        ApReqAuthChksum = 10,
        ApReqAuthSubKey = 11,
        ApRepEncryptedPart = 12,
        KrbPriv = 13,
        KrbCred = 14,
        KrbSafe = 15,
        KerbNonKerbSalt = 16,
        KerbNonKerbChksumSalt = 17,
        AcceptorSeal = 22,
        AcceptorSign = 23,
        InitiatorSeal = 24,
        InitiatorSign = 25,
        S4UX509Checksum = 26,
        [SDKName("KEY_USAGE_FAST_REQ_CHKSUM")]
        FastReqChksum = 50,
        [SDKName("KEY_USAGE_FAST_ENC")]
        FastEnc = 51,
        [SDKName("KEY_USAGE_FAST_REP")]
        FastRep = 52,
        [SDKName("KEY_USAGE_FAST_FINISHED")]
        FastFinished = 53,
        [SDKName("KEY_USAGE_ENC_CHALLENGE_CLIENT")]
        EncChallengeClient = 54,
        [SDKName("KEY_USAGE_ENC_CHALLENGE_KDC")]
        EncChallengeKDC = 55
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
