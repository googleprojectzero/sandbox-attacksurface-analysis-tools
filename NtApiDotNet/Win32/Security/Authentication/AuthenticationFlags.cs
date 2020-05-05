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

namespace NtApiDotNet.Win32.Security.Authentication
{
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

    /// <summary>
    /// Credital flags.
    /// </summary>
    public enum SecPkgCredFlags
    {
        /// <summary>
        /// Inbound credentials.
        /// </summary>
        Inbound = 0x00000001,
        /// <summary>
        /// Outbound credentials.
        /// </summary>
        Outbound = 0x00000002,
        /// <summary>
        /// Both credentials direction.
        /// </summary>
        Both = Inbound | Outbound,
        /// <summary>
        /// Default.
        /// </summary>
        Default = 0x00000004,
    }

#pragma warning disable 1591
    /// <summary>
    /// Initialize context request flags.
    /// </summary>
    [Flags]
    public enum InitializeContextReqFlags
    {
        None = 0,
        Delegate = 0x00000001,
        MutualAuth = 0x00000002,
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

    /// <summary>
    /// Initialize context return flags.
    /// </summary>
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

    /// <summary>
    /// Access context request flags.
    /// </summary>
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

    /// <summary>
    /// Accept context return flags.
    /// </summary>
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

    /// <summary>
    /// Security package capability flags.
    /// </summary>
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
}
