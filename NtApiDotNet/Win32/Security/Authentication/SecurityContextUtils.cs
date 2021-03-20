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

using NtApiDotNet.Win32.Security.Authentication.Schannel;
using NtApiDotNet.Win32.Security.Buffers;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace NtApiDotNet.Win32.Security.Authentication
{
    internal static class SecurityContextUtils
    {
        internal static T QueryContextAttributeEx<T>(SecHandle context, SECPKG_ATTR attribute) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                SecurityNativeMethods.QueryContextAttributesEx(context, attribute, buffer, buffer.Length).CheckResult();
                return buffer.Result;
            }
        }

        internal static Tuple<T, SecStatusCode> QueryContextAttributeNoThrow<T>(SecHandle context, SECPKG_ATTR attribute) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                var result = SecurityNativeMethods.QueryContextAttributes(context, attribute, buffer);
                return Tuple.Create(result != SecStatusCode.SUCCESS ? default : buffer.Result, result);
            }
        }

        internal static T QueryContextAttribute<T>(SecHandle context, SECPKG_ATTR attribute) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                SecurityNativeMethods.QueryContextAttributes(context, attribute, buffer).CheckResult();
                return buffer.Result;
            }
        }

        internal static AuthenticationPackage GetAuthenticationPackage(SecHandle context)
        {
            var pkg_info = QueryContextAttribute<SecPkgContext_PackageInfo>(context, SECPKG_ATTR.PACKAGE_INFO);
            return new AuthenticationPackage(pkg_info.PackageInfo);
        }

        internal static string GetPackageName(SecHandle context)
        {
            try
            {
                return GetAuthenticationPackage(context).Name;
            }
            catch (NtException)
            {
                return null;
            }
        }

        internal static List<SecBuffer> ToBufferList(this IEnumerable<SecurityBuffer> buffers, DisposableList list)
        {
            return buffers.Select(b => b.ToBuffer(list)).ToList();
        }

        internal static SecBufferDesc ToDesc(this IEnumerable<SecBuffer> buffers, DisposableList list)
        {
            var arr = buffers.ToArray();
            if (arr.Length == 0)
                return null;
            return list.AddResource(new SecBufferDesc(arr));
        }

        internal static void UpdateBuffers(this IList<SecurityBuffer> buffers, SecBufferDesc desc)
        {
            if (desc == null)
                return;
            var update_buffers = desc.ToArray();
            for (int i = 0; i < buffers.Count; ++i)
            {
                buffers[i].FromBuffer(update_buffers[i]);
            }
        }

        internal static void UpdateBuffers(this IEnumerable<SecurityBuffer> buffers, SecBufferDesc desc)
        {
            UpdateBuffers(buffers.ToArray(), desc);
        }

        internal static byte[] MakeSignature(
            SecHandle context,
            int flags,
            IEnumerable<SecurityBuffer> messages,
            int sequence_no)
        {
            int max_sig_size = QueryContextAttribute<SecPkgContext_Sizes>(context, SECPKG_ATTR.SIZES).cbMaxSignature;
            List<SecurityBuffer> sig_buffers = new List<SecurityBuffer>(messages);
            SecurityBufferOut signature_buffer = new SecurityBufferOut(SecurityBufferType.Token, max_sig_size);
            sig_buffers.Add(signature_buffer);

            using (var list = new DisposableList())
            {
                List<SecBuffer> buffers = sig_buffers.ToBufferList(list);
                SecBufferDesc desc = buffers.ToDesc(list);
                SecurityNativeMethods.MakeSignature(context, flags, desc, sequence_no).CheckResult();
                sig_buffers.UpdateBuffers(desc);
                return signature_buffer.ToArray();
            }
        }

        internal static byte[] MakeSignature(
            SecHandle context,
            int flags,
            byte[] message,
            int sequence_no)
        {
            return MakeSignature(context, flags, new SecurityBuffer[]
                { new SecurityBufferInOut(SecurityBufferType.Data | SecurityBufferType.ReadOnly,
                    message) }, sequence_no);
        }

        internal static bool VerifySignature(
            SecHandle context,
            IEnumerable<SecurityBuffer> messages,
            byte[] signature,
            int sequence_no)
        {
            List<SecurityBuffer> sig_buffers = new List<SecurityBuffer>(messages);
            sig_buffers.Add(new SecurityBufferInOut(SecurityBufferType.Token | SecurityBufferType.ReadOnly, signature));
            using (var list = new DisposableList())
            {
                List<SecBuffer> buffers = sig_buffers.ToBufferList(list);
                SecBufferDesc desc = buffers.ToDesc(list);
                return SecurityNativeMethods.VerifySignature(context, desc, sequence_no, out int _) == SecStatusCode.SUCCESS;
            }
        }

        internal static bool VerifySignature(
            SecHandle context,
            byte[] message,
            byte[] signature,
            int sequence_no)
        {
            return VerifySignature(context, new SecurityBuffer[]
                { new SecurityBufferInOut(SecurityBufferType.Data | SecurityBufferType.ReadOnly,
                    message) }, signature, sequence_no);
        }

        internal static EncryptedMessage EncryptMessage(
            SecHandle context,
            SecurityQualityOfProtectionFlags flags,
            byte[] message,
            int sequence_no)
        {
            if (message is null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            SecurityBuffer buffer = new SecurityBufferInOut(SecurityBufferType.Data, message);
            var signature = EncryptMessage(context, flags, new[] { buffer }, sequence_no);
            return new EncryptedMessage(buffer.ToArray(), signature);
        }

        internal static byte[] EncryptMessage(
            SecHandle context,
            SecurityQualityOfProtectionFlags flags,
            IEnumerable<SecurityBuffer> messages,
            int sequence_no)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (messages is null)
            {
                throw new ArgumentNullException(nameof(messages));
            }

            List<SecurityBuffer> sig_buffers = new List<SecurityBuffer>(messages);
            var out_sig_buffer = new SecurityBufferOut(SecurityBufferType.Token, GetSecurityTrailerSize(context));
            sig_buffers.Add(out_sig_buffer);
            EncryptMessageNoSignature(context, flags, sig_buffers, sequence_no);
            return out_sig_buffer.ToArray();
        }

        internal static void EncryptMessageNoSignature(
            SecHandle context,
            SecurityQualityOfProtectionFlags flags,
            IEnumerable<SecurityBuffer> messages,
            int sequence_no)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (messages is null)
            {
                throw new ArgumentNullException(nameof(messages));
            }

            using (var list = new DisposableList())
            {
                var buffers = messages.ToBufferList(list);
                var desc = buffers.ToDesc(list);
                SecurityNativeMethods.EncryptMessage(context, flags, desc, sequence_no).CheckResult();
                messages.UpdateBuffers(desc);
            }
        }

        internal static byte[] DecryptMessage(
            SecHandle context,
            EncryptedMessage message,
            int sequence_no)
        {
            if (message is null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            SecurityBuffer buffer = new SecurityBufferInOut(SecurityBufferType.Data, message.Message);
            DecryptMessage(context, new[] { buffer }, message.Signature, sequence_no);
            return buffer.ToArray();
        }

        internal static void DecryptMessage(
            SecHandle context,
            IEnumerable<SecurityBuffer> messages,
            byte[] signature,
            int sequence_no)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (messages is null)
            {
                throw new ArgumentNullException(nameof(messages));
            }

            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            List<SecurityBuffer> sig_buffers = new List<SecurityBuffer>(messages);
            sig_buffers.Add(new SecurityBufferInOut(SecurityBufferType.Token | SecurityBufferType.ReadOnly, signature));
            DecryptMessageNoSignature(context, sig_buffers, sequence_no);
        }

        internal static void DecryptMessageNoSignature(
            SecHandle context,
            IEnumerable<SecurityBuffer> messages,
            int sequence_no)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (messages is null)
            {
                throw new ArgumentNullException(nameof(messages));
            }

            using (var list = new DisposableList())
            {
                var buffers = messages.ToBufferList(list);
                var desc = buffers.ToDesc(list);
                SecurityNativeMethods.DecryptMessage(context, desc, sequence_no, out _).CheckResult();
                messages.UpdateBuffers(desc);
            }
        }

        internal static int GetMaxSignatureSize(SecHandle context)
        {
            return QueryContextAttribute<SecPkgContext_Sizes>(context, SECPKG_ATTR.SIZES).cbMaxSignature;
        }

        internal static int GetSecurityTrailerSize(SecHandle context)
        {
            return QueryContextAttribute<SecPkgContext_Sizes>(context, SECPKG_ATTR.SIZES).cbSecurityTrailer;
        }

        internal static SecPkgContext_StreamSizes GetStreamSizes(SecHandle context)
        {
            return QueryContextAttribute<SecPkgContext_StreamSizes>(context, SECPKG_ATTR.STREAM_SIZES);
        }

        internal static ExportedSecurityContext ExportContext(SecHandle context, SecPkgContextExportFlags export_flags, string package, bool client)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            SecBuffer buffer = new SecBuffer(SecurityBufferType.Empty);
            try
            {
                SecurityNativeMethods.ExportSecurityContext(context, export_flags,
                    buffer, out SafeKernelObjectHandle token).CheckResult();
                return new ExportedSecurityContext(package, buffer.ToArray(), !token.IsInvalid ? NtToken.FromHandle(token) : null, client);
            }
            finally
            {
                if (buffer.pvBuffer != IntPtr.Zero)
                {
                    SecurityNativeMethods.FreeContextBuffer(buffer.pvBuffer);
                }
            }
        }

        internal static SecStatusCode InitializeSecurityContext(
            CredentialHandle credential,
            SecHandle context,
            string target_name,
            InitializeContextReqFlags req_attributes,
            SecDataRep data_rep,
            IList<SecurityBuffer> input,
            SecHandle new_context,
            IList<SecurityBuffer> output,
            out InitializeContextRetFlags ret_attributes,
            LargeInteger expiry,
            bool throw_on_error)
        {
            using (DisposableList list = new DisposableList())
            {
                var input_buffers = input?.ToBufferList(list);
                var output_buffers = output?.ToBufferList(list);

                var in_buffer_desc = input_buffers.ToDesc(list);
                var out_buffer_desc = output_buffers.ToDesc(list);

                var result = SecurityNativeMethods.InitializeSecurityContext(credential.CredHandle,
                    context, target_name, req_attributes, 0, data_rep, in_buffer_desc, 0,
                    new_context, out_buffer_desc, out ret_attributes, expiry).CheckResult(throw_on_error);
                if (!result.IsSuccess())
                    return result;

                try
                {
                    if (result == SecStatusCode.SEC_I_COMPLETE_NEEDED || result == SecStatusCode.SEC_I_COMPLETE_AND_CONTINUE)
                    {
                        var comp_result = SecurityNativeMethods.CompleteAuthToken(new_context, out_buffer_desc).CheckResult(throw_on_error);
                        if (!comp_result.IsSuccess())
                            return comp_result;
                    }
                }
                finally
                {
                    if (result.IsSuccess())
                    {
                        output?.UpdateBuffers(out_buffer_desc);
                    }
                }

                return result;
            }
        }

        internal static SecStatusCode AcceptSecurityContext(
            CredentialHandle credential,
            SecHandle context,
            AcceptContextReqFlags req_attributes,
            SecDataRep data_rep,
            IList<SecurityBuffer> input,
            SecHandle new_context,
            IList<SecurityBuffer> output,
            out AcceptContextRetFlags ret_attributes,
            LargeInteger expiry,
            bool throw_on_error)
        {
            using (DisposableList list = new DisposableList())
            {
                var input_buffers = input?.ToBufferList(list);
                var output_buffers = output?.ToBufferList(list);

                var in_buffer_desc = input_buffers.ToDesc(list);
                var out_buffer_desc = output_buffers.ToDesc(list);

                SecStatusCode result = SecurityNativeMethods.AcceptSecurityContext(credential.CredHandle, context,
                    in_buffer_desc, req_attributes, data_rep, new_context, out_buffer_desc, out ret_attributes, expiry).CheckResult(throw_on_error);
                if (!result.IsSuccess())
                    return result;
                try
                {
                    if (result == SecStatusCode.SEC_I_COMPLETE_NEEDED || result == SecStatusCode.SEC_I_COMPLETE_AND_CONTINUE)
                    {
                        var comp_result = SecurityNativeMethods.CompleteAuthToken(context, out_buffer_desc).CheckResult(throw_on_error);
                        if (!comp_result.IsSuccess())
                            return comp_result;
                    }
                }
                finally
                {
                    if (result.IsSuccess())
                    {
                        output?.UpdateBuffers(out_buffer_desc);
                    }
                }

                return result;
            }
        }

        internal static byte[] GetSessionKey(SecHandle context)
        {
            var result = QueryContextAttributeNoThrow<SecPkgContext_SessionKey>(context, SECPKG_ATTR.SESSION_KEY);
            if (result.Item2 != SecStatusCode.SUCCESS)
            {
                return new byte[0];
            }

            var key = result.Item1;
            try
            {
                byte[] ret = new byte[key.SessionKeyLength];
                Marshal.Copy(key.SessionKey, ret, 0, ret.Length);
                return ret;
            }
            finally
            {
                SecurityNativeMethods.FreeContextBuffer(key.SessionKey);
            }
        }

        private static X509Certificate2 GetCertificate(SecHandle context, SECPKG_ATTR attr)
        {
            var cert = QueryContextAttribute<IntPtr>(context, attr);
            try
            {
                return new X509Certificate2(cert);
            }
            finally
            {
                SecurityNativeMethods.CertFreeCertificateContext(cert);
            }
        }

        internal static X509Certificate2 GetRemoteCertificate(SecHandle context)
        {
            return GetCertificate(context, SECPKG_ATTR.REMOTE_CERT_CONTEXT);
        }

        internal static X509Certificate2 GetLocalCertificate(SecHandle context)
        {
            return GetCertificate(context, SECPKG_ATTR.LOCAL_CERT_CONTEXT);
        }

        internal static SchannelConnectionInfo GetConnectionInfo(SecHandle context)
        {
            return new SchannelConnectionInfo(QueryContextAttribute<SecPkgContext_ConnectionInfo>(context, SECPKG_ATTR.CONNECTION_INFO));
        }
    }
}
