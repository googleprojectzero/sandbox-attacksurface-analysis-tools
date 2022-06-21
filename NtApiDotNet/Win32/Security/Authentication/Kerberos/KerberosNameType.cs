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
    /// Kerberos Name Type.
    /// </summary>
    public enum KerberosNameType
    {
        UNKNOWN = 0,
        PRINCIPAL = 1,
        SRV_INST = 2,
        SRV_HST = 3,
        SRV_XHST = 4,
        UID = 5,
        X500_PRINCIPAL = 6,
        SMTP_NAME = 7,
        ENTERPRISE_PRINCIPAL = 10,
        WELLKNOWN = 11,
        ENT_PRINCIPAL_AND_ID = -130,
        MS_PRINCIPAL = -128,
        MS_PRINCIPAL_AND_ID = -129
    }
}
