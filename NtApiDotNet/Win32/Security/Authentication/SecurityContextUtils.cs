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

using NtApiDotNet.Win32.Security.Native;
using System.IO;

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

        internal static byte[] MakeSignature(
            SecHandle context,
            int flags,
            byte[] message,
            int sequence_no)
        {
            using (var list = new DisposableList())
            {
                int max_sig_size = QueryContextAttribute<SecPkgContext_Sizes>(context, SECPKG_ATTR.SIZES).cbMaxSignature;
                SecBuffer out_sig_buffer = list.AddResource(new SecBuffer(SecBufferType.Token, max_sig_size));
                SecBuffer in_message_buffer = list.AddResource(new SecBuffer(SecBufferType.Data | SecBufferType.ReadOnly, message));
                SecBufferDesc desc = list.AddResource(new SecBufferDesc(new SecBuffer[] { in_message_buffer, out_sig_buffer }));
                SecurityNativeMethods.MakeSignature(context, flags, desc, sequence_no).CheckResult();
                return out_sig_buffer.ToArray();
            }
        }

        internal static EncryptedMessage EncryptMessage(
            SecHandle context,
            SecQopFlags flags,
            byte[] message,
            int sequence_no)
        {
            using (var list = new DisposableList())
            {
                var sizes = QueryContextAttribute<SecPkgContext_Sizes>(context, SECPKG_ATTR.SIZES);
                SecBuffer out_sig_buffer = list.AddResource(new SecBuffer(SecBufferType.Token, sizes.cbSecurityTrailer));
                SecBuffer in_out_message_buffer = list.AddResource(new SecBuffer(SecBufferType.Data, message));
                SecBufferDesc desc = list.AddResource(new SecBufferDesc(new SecBuffer[] { out_sig_buffer, in_out_message_buffer }));
                SecurityNativeMethods.EncryptMessage(context, flags, desc, sequence_no).CheckResult();
                return new EncryptedMessage(in_out_message_buffer.ToArray(), out_sig_buffer.ToArray());
            }
        }

        internal static byte[] DecryptMessage(
            SecHandle context,
            EncryptedMessage message,
            int sequence_no)
        {
            using (var list = new DisposableList())
            {
                var sizes = QueryContextAttribute<SecPkgContext_Sizes>(context, SECPKG_ATTR.SIZES);
                SecBuffer in_sig_buffer = list.AddResource(new SecBuffer(SecBufferType.Token, message.Signature));
                SecBuffer in_out_message_buffer = list.AddResource(new SecBuffer(SecBufferType.Data, message.Message));
                SecBufferDesc desc = list.AddResource(new SecBufferDesc(new SecBuffer[] { in_sig_buffer, in_out_message_buffer }));
                SecurityNativeMethods.DecryptMessage(context, desc, sequence_no, out _).CheckResult();
                return in_out_message_buffer.ToArray();
            }
        }

        internal static bool VerifySignature(
            SecHandle context,
            byte[] message,
            byte[] signature,
            int sequence_no)
        {
            using (var list = new DisposableList())
            {
                SecBuffer in_sig_buffer = list.AddResource(new SecBuffer(SecBufferType.Token | SecBufferType.ReadOnly, signature));
                SecBuffer in_message_buffer = list.AddResource(new SecBuffer(SecBufferType.Data | SecBufferType.ReadOnly, message));
                SecBufferDesc desc = list.AddResource(new SecBufferDesc(new SecBuffer[] { in_message_buffer, in_sig_buffer }));
                return SecurityNativeMethods.VerifySignature(context, desc, sequence_no, out int _).CheckResult() == SecStatusCode.Success;
            }
        }

        internal static int GetMaxSignatureSize(SecHandle context)
        {
            return QueryContextAttribute<SecPkgContext_Sizes>(context, SECPKG_ATTR.SIZES).cbMaxSignature;
        }
    }
}
