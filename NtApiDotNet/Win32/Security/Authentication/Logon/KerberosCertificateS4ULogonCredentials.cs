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
using System.Security.Cryptography.X509Certificates;

namespace NtApiDotNet.Win32.Security.Authentication.Logon
{
    /// <summary>
    /// Flags for the Certificate S4U logon.
    /// </summary>
    [Flags]
    public enum KerberosCertificateS4ULogonFlags
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("KERB_CERTIFICATE_S4U_LOGON_FLAG_CHECK_DUPLICATES")]
        CheckDuplicates = 1,
        [SDKName("KERB_CERTIFICATE_S4U_LOGON_FLAG_CHECK_LOGONHOURS")]
        CheckLogonHours = 2,
        [SDKName("KERB_CERTIFICATE_S4U_LOGON_FLAG_IF_NT_AUTH_POLICY_REQUIRED")]
        IfNtAuthPolicyRequired = 4,
        [SDKName("KERB_CERTIFICATE_S4U_LOGON_FLAG_IDENTIFY")]
        Identify = 8,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }

    /// <summary>
    /// Class to represent a KERB_CERTIFICATE_S4U_LOGON structure.
    /// </summary>
    public sealed class KerberosCertificateS4ULogonCredentials : ILsaLogonCredentials
    {
        /// <summary>
        /// Flags for the logon.
        /// </summary>
        public KerberosCertificateS4ULogonFlags Flags { get; set; }

        /// <summary>
        /// The client user principal name.
        /// </summary>
        public string UserPrincipalName { get; set; }

        /// <summary>
        /// The client domain name.
        /// </summary>
        public string DomainName { get; set; }

        /// <summary>
        /// The client's certificate.
        /// </summary>
        public X509Certificate Certificate { get; set; }

        string ILsaLogonCredentials.AuthenticationPackage => AuthenticationPackage.KERBEROS_NAME;

        SafeBuffer ILsaLogonCredentials.ToBuffer(DisposableList list)
        {
            if (Certificate is null)
                throw new ArgumentNullException(nameof(Certificate));

            var builder = new KERB_CERTIFICATE_S4U_LOGON()
            {
                MessageType = KERB_LOGON_SUBMIT_TYPE.KerbCertificateS4ULogon,
                Flags = (int)Flags
            }.ToBuilder();

            builder.AddUnicodeString(nameof(KERB_CERTIFICATE_S4U_LOGON.UserPrincipalName), UserPrincipalName);
            builder.AddUnicodeString(nameof(KERB_CERTIFICATE_S4U_LOGON.DomainName), DomainName);
            builder.AddPointerBuffer(nameof(KERB_CERTIFICATE_S4U_LOGON.Certificate),
                nameof(KERB_CERTIFICATE_S4U_LOGON.CertificateLength), Certificate.Export(X509ContentType.Cert));
            return builder.ToBuffer();
        }
    }
}
