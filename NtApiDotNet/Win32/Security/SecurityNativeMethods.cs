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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security
{
#pragma warning disable 1591
    /// <summary>
    /// Security buffer type.
    /// </summary>
    internal enum SecBufferType
    {
        Empty = 0,
        Data = 1,
        Token = 2,
        PkgParams = 3,
        Missing = 4,
        Extra = 5,
        StreamTrailer = 6,
        StreamHeader = 7,
        NegotiationInfo = 8,
        Padding = 9,
        Stream = 10,
        Mechlist = 11,
        MechlistSignature = 12,
        Target = 13,
        ChannelBindings = 14,
        ChangePassResponse = 15,
        TargetHost = 16,
        Alert = 17,
        ApplicationProtocols = 18,
        SRTPProtectionProfiles = 19,
        SRTPMasterKeyIdentifier = 20,
        TokenBinding = 21,
        PresharedKey = 22,
        PresharedKeyIdentity = 23,
        DTLAMtu = 24,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal sealed class SecBuffer : IDisposable
    {
        public int cbBuffer;
        public SecBufferType BufferType;
        public IntPtr pvBuffer;

        void IDisposable.Dispose()
        {
            if (pvBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvBuffer);
            }
        }

        public SecBuffer()
        {
        }

        public SecBuffer(SecBufferType type, byte[] data)
            : this(type, data.Length)
        {
            Marshal.Copy(data, 0, pvBuffer, data.Length);
        }

        public SecBuffer(SecBufferType type, int length)
        {
            cbBuffer = length;
            BufferType = type;
            pvBuffer = Marshal.AllocHGlobal(length);
        }

        public byte[] ToArray()
        {
            byte[] ret = new byte[cbBuffer];
            Marshal.Copy(pvBuffer, ret, 0, ret.Length);
            return ret;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal sealed class SecBufferDesc : IDisposable
    {
        const int SECBUFFER_VERSION = 0;

        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers;

        void IDisposable.Dispose()
        {
            if (pBuffers != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pBuffers);
            }
        }

        public SecBufferDesc(SecBuffer buffer) : this(new SecBuffer[] { buffer })
        {
        }

        public SecBufferDesc(SecBuffer[] buffers)
        {
            int size = Marshal.SizeOf(typeof(SecBuffer));
            ulVersion = SECBUFFER_VERSION;
            cBuffers = buffers.Length;
            pBuffers = Marshal.AllocHGlobal(buffers.Length * size);
            int offset = 0;
            foreach (var buffer in buffers)
            {
                Marshal.StructureToPtr(buffer, pBuffers + offset, false);
                offset += size;
            }
        }

        public SecBuffer[] ToArray()
        {
            SecBuffer[] buffers = new SecBuffer[cBuffers];
            int size = Marshal.SizeOf(typeof(SecBuffer));
            for (int i = 0; i < cBuffers; ++i)
            {
                buffers[i] = (SecBuffer)Marshal.PtrToStructure(pBuffers + (i * size), typeof(SecBuffer));
            }
            return buffers;
        }
    }

    internal enum SecWinNtAuthIdentityFlags
    {
        Ansi = 0x1,
        Unicode = 0x2,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class SEC_WINNT_AUTH_IDENTITY_EX
    {
        const int SEC_WINNT_AUTH_IDENTITY_VERSION = 0x200;

        public int Version;
        public int Length;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string User;
        public int UserLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Domain;
        public int DomainLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Password;
        public int PasswordLength;
        public SecWinNtAuthIdentityFlags Flags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string PackageList;
        public int PackageListLength;

        public SEC_WINNT_AUTH_IDENTITY_EX(string user, string domain, string password)
        {
            Version = SEC_WINNT_AUTH_IDENTITY_VERSION;
            Length = Marshal.SizeOf(this);
            User = user;
            UserLength = user?.Length ?? 0;
            Domain = domain;
            DomainLength = domain?.Length ?? 0;
            Password = password;
            PasswordLength = password?.Length ?? 0;
            Flags = SecWinNtAuthIdentityFlags.Unicode;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class SecHandle
    {
        public IntPtr dwLower;
        public IntPtr dwUpper;
    }

    /// <summary>
    /// Security data representation.
    /// </summary>
    public enum SecDataRep
    {
        /// <summary>
        /// Native representation.
        /// </summary>
        Native = 0x00000010,
        /// <summary>
        /// Network representation.
        /// </summary>
        Network = 0x00000000
    }

    public enum SecPkgCredFlags
    {
        Inbound = 0x00000001,
        Outbound = 0x00000002,
        Both = Inbound | Outbound,
        Default = 0x00000004,
    }

    [Flags]
    public enum InitializeContextReqFlags
    {
        None = 0,
        Delegate = 0x00000001,
        MutalAuth = 0x00000002,
        ReplayDetect = 0x00000004,
        SequenceDetect = 0x00000008,
        Confidentiality = 0x00000010,
        UseSessionKey = 0x00000020,
        PromptForCreds = 0x00000040,
        UseSuppliedCreds = 0x00000080,
        AllocateMemory = 0x00000100,
        UseDCEStyle = 0x00000200,
        Datagram = 0x00000400,
        Connection = 0x00000800,
        CallLevel = 0x00001000,
        FragmentSupplied = 0x00002000,
        ExtendedError = 0x00004000,
        Stream = 0x00008000,
        Integrity = 0x00010000,
        Identity = 0x00020000,
        NullSession = 0x00040000,
        ManualCredValidation = 0x00080000,
        Reserved1 = 0x00100000,
        FragmentToFit = 0x00200000,
        ForwardCredentials = 0x00400000,
        NoIntegrity = 0x00800000,
        UseHttpStyle = 0x01000000,
        UnverifiedTargetName = 0x20000000,
        ConfidentialityOnly = 0x40000000,
    }

    [Flags]
    public enum InitializeContextRetFlags
    {
        None = 0,
        Delegate = 0x00000001,
        MutualAuth = 0x00000002,
        ReplayDetect = 0x00000004,
        SequenceDetect = 0x00000008,
        Confidentiality = 0x00000010,
        UseSessionKey = 0x00000020,
        UsedCollectedCreds = 0x00000040,
        UsedSuppliedCreds = 0x00000080,
        AllocatedMemory = 0x00000100,
        UsedDceStyle = 0x00000200,
        Datagram = 0x00000400,
        Connection = 0x00000800,
        IntermediateReturn = 0x00001000,
        CallLevel = 0x00002000,
        ExtendedError = 0x00004000,
        Stream = 0x00008000,
        Integrity = 0x00010000,
        Identify = 0x00020000,
        NullSession = 0x00040000,
        ManualCredValidation = 0x00080000,
        Reserved1 = 0x00100000,
        FragmentOnly = 0x00200000,
        ForwardCredentials = 0x00400000,
        UsedHttpStyle = 0x01000000,
        NoAdditionalToken = 0x02000000,
        Reauthentication = 0x08000000,
        ConfidentialityOnly = 0x40000000,
    }

    [Flags]
    public enum AcceptContextReqFlags
    {
        None = 0,
        Delegate = 0x00000001,
        MutualAuth = 0x00000002,
        ReplayDetect = 0x00000004,
        SequenceDetect = 0x00000008,
        Confidentiality = 0x00000010,
        UseSessionKey = 0x00000020,
        SessionTicket = 0x00000040,
        AllocateMemory = 0x00000100,
        UseDceStyle = 0x00000200,
        Datagram = 0x00000400,
        Connection = 0x00000800,
        CallLevel = 0x00001000,
        FragmentSupplied = 0x00002000,
        ExtendedError = 0x00008000,
        Stream = 0x00010000,
        Integrity = 0x00020000,
        Licensing = 0x00040000,
        Identify = 0x00080000,
        AllowNullSessions = 0x00100000,
        AllowNonUserLogons = 0x00200000,
        AllowContextReplay = 0x00400000,
        FragmentToFit = 0x00800000,
    }

    [Flags]
    public enum AcceptContextRetFlags
    {
        None = 0,
        Delegate = 0x00000001,
        MutualAuth = 0x00000002,
        ReplayDetect = 0x00000004,
        SequenceDetect = 0x00000008,
        Confidentiality = 0x00000010,
        UseSessionKey = 0x00000020,
        SessionTicket = 0x00000040,
        AllocatedMemory = 0x00000100,
        UsedDceStyle = 0x00000200,
        Datagram = 0x00000400,
        Connection = 0x00000800,
        CallLevel = 0x00002000,
        ThirdLegFailed = 0x00004000,
        ExtendedError = 0x00008000,
        Stream = 0x00010000,
        Integrity = 0x00020000,
        Licensing = 0x00040000,
        Identify = 0x00080000,
        NullSession = 0x00100000,
        AllowNonUserLogons = 0x00200000,
        AllowContextReplay = 0x00400000,
        FragmentOnly = 0x00800000,
        NoToken = 0x01000000,
        NoAdditionalToken = 0x02000000,
    }

    internal enum SecStatusCode : uint
    {
        Success = 0,
        ContinueNeeded = 0x00090312,
        CompleteNeeded = 0x00090313,
        CompleteAndContinue = 0x00090314,
    }

    [Flags]
    public enum SecPkgCapabilityFlag
    {
        Integrity = 0x00000001,
        Private = 0x00000002,
        TokenOnly = 0x00000004,
        Datagram = 0x00000008,
        Connection = 0x00000010,
        MultiRequired = 0x00000020,
        ClientOnly = 0x00000040,
        ExtendedError = 0x00000080,
        Impersonation = 0x00000100,
        AcceptWin32Name = 0x00000200,
        Stream = 0x00000400,
        Negotiable = 0x00000800,
        GssCompatible = 0x00001000,
        Logon = 0x00002000,
        AsciiBuffers = 0x00004000,
        Fragment = 0x00008000,
        MutualAuth = 0x00010000,
        Delegation = 0x00020000,
        ReadOnlyWithChecksum = 0x00040000,
        RestrictedTokens = 0x00080000,
        NegoExtended = 0x00100000,
        Negotiable2 = 0x00200000,
        AppContainerPassthrough = 0x00400000,
        AppContainerChecks = 0x00800000,
        CredentialIsolationEnabled = 0x01000000,
        ApplyLoopback = 0x02000000,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SecPkgInfo
    {
        public SecPkgCapabilityFlag fCapabilities;
        public short wVersion;
        public short wRPCID;
        public int cbMaxToken;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Name;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Comment;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class OptionalLuid
    {
        public Luid luid;
    }

    internal static class SecurityNativeMethods
    {
        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode AcquireCredentialsHandle(
            string pszPrincipal,
            string pszPackage,
            SecPkgCredFlags fCredentialUse,
            OptionalLuid pvLogonId,
            SEC_WINNT_AUTH_IDENTITY_EX pAuthData,
            IntPtr pGetKeyFn,
            IntPtr pvGetKeyArgument,
            [Out] SecHandle phCredential,
            [Out] LargeInteger ptsExpiry
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode FreeCredentialsHandle([In, Out] SecHandle phCredential);

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode InitializeSecurityContext(
            [In] SecHandle phCredential,
            [In] SecHandle phContext,
            string pszTargetName,
            InitializeContextReqFlags fContextReq,
            int Reserved1,
            SecDataRep TargetDataRep,
            SecBufferDesc pInput,
            int Reserved2,
            [Out] SecHandle phNewContext,
            [In, Out] SecBufferDesc pOutput,
            out InitializeContextRetFlags pfContextAttr,
            [Out] LargeInteger ptsExpiry
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode CompleteAuthToken(SecHandle phContext,
            SecBufferDesc pToken
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode DeleteSecurityContext(
            SecHandle phContext
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode AcceptSecurityContext(
            [In] SecHandle phCredential,
            [In] SecHandle phContext,
            SecBufferDesc pInput,
            AcceptContextReqFlags fContextReq,
            SecDataRep TargetDataRep,
            [In, Out] SecHandle phNewContext,
            [In, Out] SecBufferDesc pOutput,
            out AcceptContextRetFlags pfContextAttr,
            [Out] LargeInteger ptsExpiry
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode QuerySecurityContextToken(SecHandle phContext, out SafeKernelObjectHandle Token);

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode FreeContextBuffer(
          IntPtr pvContextBuffer
        );

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        internal static extern SecStatusCode EnumerateSecurityPackages(
            out int pcPackages,
            out IntPtr ppPackageInfo
        );

        public static SecStatusCode CheckResult(this SecStatusCode result)
        {
            if (result < 0)
            {
                throw new NtException((NtStatus)(uint)result);
            }
            return result;
        }
    }
}
