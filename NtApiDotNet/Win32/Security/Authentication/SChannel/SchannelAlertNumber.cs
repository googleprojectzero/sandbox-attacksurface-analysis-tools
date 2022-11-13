//  Copyright 2021 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Security.Authentication.Schannel
{
    /// <summary>
    /// Schannel Alert Number.
    /// </summary>
    public enum SchannelAlertNumber
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("TLS1_ALERT_CLOSE_NOTIFY")] CloseNotify = 0, // warning
        [SDKName("TLS1_ALERT_UNEXPECTED_MESSAGE")] UnexpectedMessage = 10, // error
        [SDKName("TLS1_ALERT_BAD_RECORD_MAC")] BadRecordMAC = 20, // error
        [SDKName("TLS1_ALERT_DECRYPTION_FAILED")] DecryptionFailed = 21, // reserved
        [SDKName("TLS1_ALERT_RECORD_OVERFLOW")] RecordOverflow = 22, // error
        [SDKName("TLS1_ALERT_DECOMPRESSION_FAIL")] DecompressionFail = 30, // error
        [SDKName("TLS1_ALERT_HANDSHAKE_FAILURE")] HandshakeFailure = 40, // error
        [SDKName("TLS1_ALERT_BAD_CERTIFICATE")] BadCertificate = 42, // warning or error
        [SDKName("TLS1_ALERT_UNSUPPORTED_CERT")] UnsupportedCert = 43, // warning or error
        [SDKName("TLS1_ALERT_CERTIFICATE_REVOKED")] CertificateRevoked = 44, // warning or error
        [SDKName("TLS1_ALERT_CERTIFICATE_EXPIRED")] CertificateExpired = 45, // warning or error
        [SDKName("TLS1_ALERT_CERTIFICATE_UNKNOWN")] CertificateUnknown = 46, // warning or error
        [SDKName("TLS1_ALERT_ILLEGAL_PARAMETER")] IllegalParameter = 47, // error
        [SDKName("TLS1_ALERT_UNKNOWN_CA")] UnknownCA = 48, // error
        [SDKName("TLS1_ALERT_ACCESS_DENIED")] AccessDenied = 49, // error
        [SDKName("TLS1_ALERT_DECODE_ERROR")] DecodeError = 50, // error
        [SDKName("TLS1_ALERT_DECRYPT_ERROR")] DecryptError = 51, // error
        [SDKName("TLS1_ALERT_EXPORT_RESTRICTION")] ExportRestriction = 60, // reserved
        [SDKName("TLS1_ALERT_PROTOCOL_VERSION")] ProtocolVersion = 70, // error
        [SDKName("TLS1_ALERT_INSUFFIENT_SECURITY")] InsufficientSecurity = 71, // error
        [SDKName("TLS1_ALERT_INTERNAL_ERROR")] InternalError = 80, // error
        [SDKName("TLS1_ALERT_USER_CANCELED")] UserCancelled = 90, // warning or error
        [SDKName("TLS1_ALERT_NO_RENEGOTIATION")] NoRenogotiation = 100, // warning
        [SDKName("TLS1_ALERT_UNSUPPORTED_EXT")] UnsupportedExt = 110, // error
        [SDKName("TLS1_ALERT_UNKNOWN_PSK_IDENTITY")] UnknownPskIdentity = 115, // error
        [SDKName("TLS1_ALERT_NO_APP_PROTOCOL")] NoAppProtocol = 120, // error
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
