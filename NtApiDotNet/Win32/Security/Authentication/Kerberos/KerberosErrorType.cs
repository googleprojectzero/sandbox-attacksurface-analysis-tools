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
    /// Kerberos Error Type.
    /// </summary>
    public enum KerberosErrorType
    {
        NONE = 0,
        NAME_EXP = 1,
        SERVICE_EXP = 2,
        BAD_PVNO = 3,
        C_OLD_MAST_KVNO = 4,
        S_OLD_MAST_KVNO = 5,
        C_PRINCIPAL_UNKNOWN = 6,
        S_PRINCIPAL_UNKNOWN = 7,
        PRINCIPAL_NOT_UNIQUE = 8,
        NULL_KEY = 9,
        CANNOT_POSTDATE = 10,
        NEVER_VALID = 11,
        POLICY = 12,
        BADOPTION = 13,
        ENCTYPE_NOSUPP = 14,
        SUMTYPE_NOSUPP = 15,
        PADATA_TYPE_NOSUPP = 16,
        TRTYPE_NOSUPP = 17,
        CLIENT_REVOKED = 18,
        SERVICE_REVOKED = 19,
        TGT_REVOKED = 20,
        CLIENT_NOTYET = 21,
        SERVICE_NOTYET = 22,
        KEY_EXP = 23,
        PREAUTH_FAILED = 24,
        PREAUTH_REQUIRED = 25,
        SERVER_NOMATCH = 26,
        MUST_USE_USER2USER = 27,
        PATH_NOT_ACCEPTED = 28,
        SVC_UNAVAILABLE = 29,
        BAD_INTEGRITY = 31,
        TKT_EXPIRED = 32,
        TKT_NYV = 33,
        REPEAT = 34,
        NOT_US = 35,
        BADMATCH = 36,
        SKEW = 37,
        BADADDR = 38,
        BADVERSION = 39,
        MSG_TYPE = 40,
        MODIFIED = 41,
        BADORDER = 42,
        BADKEYVER = 44,
        NOKEY = 45,
        MUT_FAIL = 46,
        BADDIRECTION = 47,
        METHOD = 48,
        BADSEQ = 49,
        INAPP_CKSUM = 50,
        AP_PATH_NOT_ACCEPTED = 51,
        RESPONSE_TOO_BIG = 52,
        GENERIC = 60,
        FIELD_TOOLONG = 61,
    }
}
