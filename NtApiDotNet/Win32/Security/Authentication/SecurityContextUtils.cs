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

using NtApiDotNet.Win32.Security.Buffers;
using NtApiDotNet.Win32.Security.Native;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication
{
    internal static class SecurityContextUtils
    {
        internal static T QueryContextAttribute<T>(SecHandle context, SECPKG_ATTR attribute) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                SecurityNativeMethods.QueryContextAttributesEx(context, attribute, buffer, buffer.Length).CheckResult();
                return buffer.Result;
            }
        }

        internal static AuthenticationPackage GetAuthenticationPackage(SecHandle context)
        {
            var pkg_info = QueryContextAttribute<SecPkgContext_PackageInfo>(context, SECPKG_ATTR.PACKAGE_INFO);
            return new AuthenticationPackage(pkg_info.PackageInfo);
        }

        internal static List<SecBuffer> ToBufferList(this List<SecurityBuffer> buffers, DisposableList list)
        {
            return buffers.Select(b => list.AddResource(b.ToBuffer())).ToList();
        }

        internal static SecBufferDesc ToDesc(this List<SecBuffer> buffers, DisposableList list)
        {
            return list.AddResource(new SecBufferDesc(buffers.ToArray()));
        }

        internal static void UpdateBuffers(this List<SecurityBuffer> buffers, List<SecBuffer> update_buffers)
        {
            for (int i = 0; i < buffers.Count; ++i)
            {
                buffers[i].FromBuffer(update_buffers[i]);
            }
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
                sig_buffers.UpdateBuffers(buffers);
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
                return SecurityNativeMethods.VerifySignature(context, desc, sequence_no, out int _) == SecStatusCode.Success;
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
            SecQopFlags flags,
            byte[] message,
            int sequence_no)
        {
            SecurityBuffer buffer = new SecurityBufferInOut(SecurityBufferType.Data, message);
            var signature = EncryptMessage(context, flags, new[] { buffer }, sequence_no);
            return new EncryptedMessage(buffer.ToArray(), signature);
        }

        internal static byte[] EncryptMessage(
            SecHandle context,
            SecQopFlags flags,
            IEnumerable<SecurityBuffer> messages,
            int sequence_no)
        {
            List<SecurityBuffer> sig_buffers = new List<SecurityBuffer>(messages);
            var sizes = QueryContextAttribute<SecPkgContext_Sizes>(context, SECPKG_ATTR.SIZES);
            var out_sig_buffer = new SecurityBufferOut(SecurityBufferType.Token, sizes.cbSecurityTrailer);
            sig_buffers.Add(out_sig_buffer);

            using (var list = new DisposableList())
            {
                var buffers = sig_buffers.ToBufferList(list);
                var desc = buffers.ToDesc(list);
                SecurityNativeMethods.EncryptMessage(context, flags, desc, sequence_no).CheckResult();
                sig_buffers.UpdateBuffers(buffers);
                return out_sig_buffer.ToArray();
            }
        }

        internal static byte[] DecryptMessage(
            SecHandle context,
            EncryptedMessage message,
            int sequence_no)
        {
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
            List<SecurityBuffer> sig_buffers = new List<SecurityBuffer>(messages);
            sig_buffers.Add(new SecurityBufferInOut(SecurityBufferType.Token | SecurityBufferType.ReadOnly, signature));

            using (var list = new DisposableList())
            {
                var buffers = sig_buffers.ToBufferList(list);
                var desc = buffers.ToDesc(list);
                SecurityNativeMethods.DecryptMessage(context, desc, sequence_no, out _).CheckResult();
                sig_buffers.UpdateBuffers(buffers);
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

        internal static ExportedSecurityContext ExportContext(SecHandle context, SecPkgContextExportFlags export_flags, string package)
        {
            using (SecBuffer buffer = new SecBuffer(SecurityBufferType.Empty, 64 * 1024))
            {
                SecurityNativeMethods.ExportSecurityContext(context, SecPkgContextExportFlags.None,
                    buffer, out SafeKernelObjectHandle token).CheckResult();
                return new ExportedSecurityContext(package, buffer.ToArray(), NtToken.FromHandle(token));
            }
        }
    }
}
