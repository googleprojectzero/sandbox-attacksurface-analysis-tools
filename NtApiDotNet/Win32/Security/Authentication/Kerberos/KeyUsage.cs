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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    internal enum KeyUsage
    {
        AsReqPaEncTimestamp = 1,
        AsRepTgsRepTicket = 2,
        AsRepEncryptedPart = 3,
        TgsReqKdcReqBodySessionKey = 4,
        TgsReqKdcReqBodyAuthSubkey = 5,
        TgsReqPaTgsReqApReqChksum = 6,
        TgsReqPaTgaReqApReq = 7,
        TgsRepEncryptedPart = 8,
        TgsRepEncryptionPartAuthSubkey = 9,
        ApReqAuthChksum = 10,
        ApReqAuthSubKey = 11,
        ApRepEncryptedPart = 12,
        KrbPriv = 13,
        KrbCred = 14,
        KrbSafe = 15
    }
}
