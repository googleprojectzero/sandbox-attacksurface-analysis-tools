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

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// RPC authentication type.
    /// </summary>
    public enum RpcAuthenticationType
    {
        /// <summary>
        /// Default. Uses WinNT.
        /// </summary>
        [SDKName("RPC_C_AUTHN_DEFAULT")]
        Default = -1,

        /// <summary>
        /// No authentication.
        /// </summary>
        [SDKName("RPC_C_AUTHN_NONE")]
        None = 0,

        /// <summary>
        /// DCE private.
        /// </summary>
        [SDKName("RPC_C_AUTHN_DCE_PRIVATE")]
        DCEPrivate = 1,

        /// <summary>
        /// DCE public.
        /// </summary>
        [SDKName("RPC_C_AUTHN_DCE_PUBLIC")]
        DCEPublic = 2,

        /// <summary>
        /// DEC public.
        /// </summary>
        [SDKName("RPC_C_AUTHN_DEC_PUBLIC")]
        DECPublic = 4,

        /// <summary>
        /// SPNEGO authentication.
        /// </summary>
        [SDKName("RPC_C_AUTHN_GSS_NEGOTIATE")]
        Negotiate = 9,

        /// <summary>
        /// WinNT authentication, i.e. NTLM.
        /// </summary>
        [SDKName("RPC_C_AUTHN_WINNT")]
        WinNT = 10,

        /// <summary>
        /// Secure channel.
        /// </summary>
        [SDKName("RPC_C_AUTHN_GSS_SCHANNEL")]
        Schannel = 14,

        /// <summary>
        /// Kerberos.
        /// </summary>
        [SDKName("RPC_C_AUTHN_GSS_KERBEROS")]
        Kerberos = 16,

        /// <summary>
        /// DPA.
        /// </summary>
        [SDKName("RPC_C_AUTHN_DPA")]
        DPA = 17,

        /// <summary>
        /// MSN.
        /// </summary>
        [SDKName("RPC_C_AUTHN_MSN")]
        MSN = 18,

        /// <summary>
        /// Digest.
        /// </summary>
        [SDKName("RPC_C_AUTHN_DIGEST")]
        Digest = 21,

        /// <summary>
        /// Kernel.
        /// </summary>
        [SDKName("RPC_C_AUTHN_KERNEL")]
        Kernel = 20,

        /// <summary>
        /// SPNEGO extender.
        /// </summary>
        [SDKName("RPC_C_AUTHN_NEGO_EXTENDER")]
        NegoExtender = 30,

        /// <summary>
        /// PKU2U
        /// </summary>
        [SDKName("RPC_C_AUTHN_PKU2U")]
        PKU2U = 31,

        /// <summary>
        /// LiveSSP
        /// </summary>
        [SDKName("RPC_C_AUTHN_LIVE_SSP")]
        LiveSSP = 32,

        /// <summary>
        /// LiveXP SSP.
        /// </summary>
        [SDKName("RPC_C_AUTHN_LIVEXP_SSP")]
        LiveXPSSP = 35,

        /// <summary>
        /// CloudAP.
        /// </summary>
        [SDKName("RPC_C_AUTHN_CLOUD_AP")]
        CloudAP = 36,

        /// <summary>
        /// MS Online.
        /// </summary>
        [SDKName("RPC_C_AUTHN_MSONLINE")]
        MSOnline = 82,

        /// <summary>
        /// Message Queue.
        /// </summary>
        [SDKName("RPC_C_AUTHN_MQ")]
        MQ = 100,
    }
}
