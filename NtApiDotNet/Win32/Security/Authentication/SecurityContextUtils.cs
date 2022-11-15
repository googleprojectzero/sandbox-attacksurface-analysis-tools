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

using NtApiDotNet.Utilities.Memory;
using NtApiDotNet.Win32.Security.Authentication.Schannel;
using NtApiDotNet.Win32.Security.Buffers;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
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
            return new AuthenticationPackage(pkg_info.PackageInfo.ReadStruct<SecPkgInfo>());
        }

        internal static string GetPackageName(SecHandle context)
        {
            if (context != null)
            {
                try
                {
                    return GetAuthenticationPackage(context).Name;
                }
                catch (NtException)
                {
                }
            }

            return null;
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

            using (var desc = SecurityBufferDescriptor.Create(sig_buffers))
            {
                SecurityNativeMethods.MakeSignature(context, flags, desc.Value, sequence_no).CheckResult();
                desc.UpdateBuffers();
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
                { new SecurityBufferInOut(SecurityBufferType.Data,
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
            using (var desc = SecurityBufferDescriptor.Create(sig_buffers))
            {
                return SecurityNativeMethods.VerifySignature(context, desc.Value, 
                    sequence_no, out int _) == SecStatusCode.SUCCESS;
            }
        }

        internal static bool VerifySignature(
            SecHandle context,
            byte[] message,
            byte[] signature,
            int sequence_no)
        {
            return VerifySignature(context, new SecurityBuffer[]
                { new SecurityBufferInOut(SecurityBufferType.Data,
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

            using (var desc = SecurityBufferDescriptor.Create(messages))
            {
                SecurityNativeMethods.EncryptMessage(context, flags, desc.Value, sequence_no).CheckResult();
                desc.UpdateBuffers();
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

            using (var desc = SecurityBufferDescriptor.Create(messages))
            {
                SecurityNativeMethods.DecryptMessage(context, desc.Value, sequence_no, out _).CheckResult();
                desc.UpdateBuffers();
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

        internal static bool GetIsLoopback(SecHandle context)
        {
            var res = QueryContextAttributeNoThrow<int>(context, SECPKG_ATTR.IS_LOOPBACK);
            return res.Item1 != 0;
        }

        internal static SecurityChannelBinding GetChannelBinding(SecHandle context, SECPKG_ATTR attr)
        {
            var target = QueryContextAttributeNoThrow<SecPkgContext_Bindings>(context, attr);
            if (target.Item2 == SecStatusCode.SUCCESS)
            {
                try
                {
                    var binding = target.Item1;
                    if (binding.BindingsLength == 0 || binding.Bindings == IntPtr.Zero)
                        return null;

                    var buffer = new SafeStructureInOutBuffer<SEC_CHANNEL_BINDINGS>(binding.Bindings, binding.BindingsLength, false);
                    return new SecurityChannelBinding(buffer);
                }
                finally
                {
                    SecurityNativeMethods.FreeContextBuffer(target.Item1.Bindings);
                }
            }
            return null;
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
            using (SecurityBufferDescriptor in_buffer_desc = SecurityBufferDescriptor.Create(input), 
                out_buffer_desc = SecurityBufferDescriptor.Create(output))
            {
                var result = SecurityNativeMethods.InitializeSecurityContext(credential.CredHandle,
                    context, target_name, req_attributes, 0, data_rep, in_buffer_desc.Value, 0,
                    new_context, out_buffer_desc.Value, out ret_attributes, expiry).CheckResult(throw_on_error);
                if (!result.IsSuccess())
                    return result;

                try
                {
                    if (result == SecStatusCode.SEC_I_COMPLETE_NEEDED || result == SecStatusCode.SEC_I_COMPLETE_AND_CONTINUE)
                    {
                        var comp_result = SecurityNativeMethods.CompleteAuthToken(new_context, out_buffer_desc.Value).CheckResult(throw_on_error);
                        if (!comp_result.IsSuccess())
                            return comp_result;
                    }
                }
                finally
                {
                    if (result.IsSuccess())
                    {
                        out_buffer_desc.UpdateBuffers();
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
            using (SecurityBufferDescriptor in_buffer_desc = SecurityBufferDescriptor.Create(input),
                out_buffer_desc = SecurityBufferDescriptor.Create(output))
            {
                SecStatusCode result = SecurityNativeMethods.AcceptSecurityContext(credential.CredHandle, context,
                    in_buffer_desc.Value, req_attributes, data_rep, new_context, 
                    out_buffer_desc.Value, out ret_attributes, expiry).CheckResult(throw_on_error);
                if (!result.IsSuccess())
                    return result;
                try
                {
                    if (result == SecStatusCode.SEC_I_COMPLETE_NEEDED || result == SecStatusCode.SEC_I_COMPLETE_AND_CONTINUE)
                    {
                        var comp_result = SecurityNativeMethods.CompleteAuthToken(context, out_buffer_desc.Value).CheckResult(throw_on_error);
                        if (!comp_result.IsSuccess())
                            return comp_result;
                    }
                }
                finally
                {
                    if (result.IsSuccess())
                    {
                        out_buffer_desc.UpdateBuffers();
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

        internal static AuthenticationContextKeyInfo GetKeyInfo(SecHandle context)
        {
            using (var key_info = QueryContextAttribute<SecPkgContext_KeyInfo>(context, SECPKG_ATTR.KEY_INFO))
            {
                return new AuthenticationContextKeyInfo(key_info);
            }
        }

        internal static SecStatusCode ApplyControlToken(SecHandle context, IEnumerable<SecurityBuffer> input, bool throw_on_error)
        {
            using (var desc = SecurityBufferDescriptor.Create(input))
            {
                return SecurityNativeMethods.ApplyControlToken(context, desc.Value).CheckResult(throw_on_error);
            }
        }
    }
}
