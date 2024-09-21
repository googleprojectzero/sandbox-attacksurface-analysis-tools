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
    /// Kerberos Pre-Authentication Data Types.
    /// </summary>
    public enum KerberosPreAuthenticationType
    {
        None = 0,
        PA_TGS_REQ = 1,
        PA_ENC_TIMESTAMP = 2,
        PA_PW_SALT = 3,
        Reserved = 4,
        PA_ENC_UNIX_TIME = 5,
        PA_SANDIA_SECUREID = 6,
        PA_SESAME = 7,
        PA_OSF_DCE = 8,
        PA_CYBERSAFE_SECUREID = 9,
        PA_AFS3_SALT = 10,
        PA_ETYPE_INFO = 11,
        PA_SAM_CHALLENGE = 12,
        PA_SAM_RESPONSE = 13,
        PA_PK_AS_REQ_OLD = 14,
        PA_PK_AS_REP_OLD = 15,
        PA_PK_AS_REQ = 16,
        PA_PK_AS_REP = 17,
        PA_PK_OCSP_RESPONSE = 18,
        PA_ETYPE_INFO2 = 19,
        PA_USE_SPECIFIED_KVNO = 20,
        PA_SAM_REDIRECT = 21,
        PA_GET_FROM_TYPED_DATA = 22,
        TD_PADATA = 22,
        PA_SAM_ETYPE_INFO = 23,
        PA_ALT_PRINC = 24,
        PA_SAM_CHALLENGE2 = 30,
        PA_SAM_RESPONSE2 = 31,
        PA_EXTRA_TGT = 41,
        TD_PKINIT_CMS_CERTIFICATES = 101,
        TD_KRB_PRINCIPAL = 102,
        TD_KRB_REALM = 103,
        TD_TRUSTED_CERTIFIERS = 104,
        TD_CERTIFICATE_INDEX = 105,
        TD_APP_DEFINED_ERROR = 106,
        TD_REQ_NONCE = 107,
        TD_REQ_SEQ = 108,
        PA_PAC_REQUEST = 128,
        PA_FOR_USER = 129,
        PA_S4U_X509_USER = 130,
        PA_FX_COOKIE = 133,
        PA_AUTHENTICATION_SET = 134,
        PA_AUTH_SET_SELECTED = 135,
        PA_FX_FAST = 136,
        PA_FX_ERROR = 137,
        PA_ENCRYPTED_CHALLENGE = 138,
        PA_AS_FRESHNESS = 150,
        KERB_KEY_LIST_REQ = 161,
        KERB_KEY_LIST_REP = 162,
        PA_SUPPORTED_ENCTYPES = 165,
        PA_PAC_OPTIONS = 167,
    }
}
