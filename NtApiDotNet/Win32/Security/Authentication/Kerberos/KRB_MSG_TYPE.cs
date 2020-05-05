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
#pragma warning disable 1591
    /// <summary>
    /// Kerberos Message Type.
    /// </summary>
    public enum KRB_MSG_TYPE
    {
        KRB_AS_REQ  = 10,
        KRB_AS_REP  = 11,
        KRB_TGS_REQ = 12,
        KRB_TGS_REP = 13,
        KRB_AP_REQ = 14,
        KRB_AP_REP = 15,
        KRB_TGT_REQ = 16,
        KRB_TGT_REP = 17,
        KRB_SAFE = 20,
        KRB_PRIV = 21,
        KRB_CRED = 22,
        KRB_ERROR = 30,
    }
}
