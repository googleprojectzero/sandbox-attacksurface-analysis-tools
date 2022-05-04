//  Copyright 2022 Google LLC. All Rights Reserved.
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
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication.Logon
{
    /// <summary>
    /// Flags for the certificate logon.
    /// </summary>
    [Flags]
    public enum KerberosCertificateLogonFlags
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES")]
        CheckDuplicates = 0x1,
        [SDKName("KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO")]
        UseCertificateInfo = 0x2,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }

    /// <summary>
    /// Class to represent a KERB_CERTIFICATE_LOGON structure.
    /// </summary>
    public class KerberosCertificateLogonCredentials : ILsaLogonCredentials
    {
        /// <summary>
        /// The domain name.
        /// </summary>
        public string DomainName { get; set; }
        /// <summary>
        /// The user name.
        /// </summary>
        public string UserName { get; set; }
        /// <summary>
        /// The PIN for the certificate.
        /// </summary>
        public string Pin { get; set; }
        /// <summary>
        /// Flags.
        /// </summary>
        public KerberosCertificateLogonFlags Flags { get; set; }
        /// <summary>
        /// The CSP data.
        /// </summary>
        public KerberosCertificateLogonData CspData { get; set; }

        SafeBuffer ILsaLogonCredentials.ToBuffer(DisposableList list)
        {
            if (CspData is null)
            {
                throw new ArgumentNullException(nameof(CspData));
            }

            KerberosCertificateLogonFlags flags = Flags;

            if (CspData is KerberosCertificateHashInfo)
            {
                flags |= KerberosCertificateLogonFlags.UseCertificateInfo;
            }

            var builder = new KERB_CERTIFICATE_LOGON()
            {
                MessageType = KERB_LOGON_SUBMIT_TYPE.KerbCertificateLogon,
                Flags = (int)flags
            }.ToBuilder();

            builder.AddUnicodeString(nameof(KERB_CERTIFICATE_LOGON.UserName), UserName);
            builder.AddUnicodeString(nameof(KERB_CERTIFICATE_LOGON.DomainName), DomainName);
            builder.AddUnicodeString(nameof(KERB_CERTIFICATE_LOGON.Pin), Pin);
            builder.AddPointerBuffer(nameof(KERB_CERTIFICATE_LOGON.CspData), 
                nameof(KERB_CERTIFICATE_LOGON.CspDataLength), CspData.ToArray());
            return builder.ToBuffer();
        }
    }
}
