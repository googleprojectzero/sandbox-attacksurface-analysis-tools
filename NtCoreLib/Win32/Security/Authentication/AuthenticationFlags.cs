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

using NtCoreLib.Utilities.Reflection;
using System;

namespace NtCoreLib.Win32.Security.Authentication;

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
    /// <summary>
    /// Auto logon restricted. Don't use automatic credentials.
    /// </summary>
    AutoLogonRestricted = 0x00000010,
    /// <summary>
    /// Only process policy.
    /// </summary>
    ProcessPolicyOnly = 0x00000020,
}

#pragma warning disable 1591
/// <summary>
/// Initialize context request flags.
/// </summary>
[Flags]
public enum InitializeContextReqFlags
{
    None = 0,
    [SDKName("ISC_REQ_DELEGATE")]
    Delegate = 0x00000001,
    [SDKName("ISC_REQ_MUTUAL_AUTH")]
    MutualAuth = 0x00000002,
    [SDKName("ISC_REQ_REPLAY_DETECT")]
    ReplayDetect = 0x00000004,
    [SDKName("ISC_REQ_SEQUENCE_DETECT")]
    SequenceDetect = 0x00000008,
    [SDKName("ISC_REQ_CONFIDENTIALITY")]
    Confidentiality = 0x00000010,
    [SDKName("ISC_REQ_USE_SESSION_KEY")]
    UseSessionKey = 0x00000020,
    [SDKName("ISC_REQ_PROMPT_FOR_CREDS")]
    PromptForCreds = 0x00000040,
    [SDKName("ISC_REQ_USE_SUPPLIED_CREDS")]
    UseSuppliedCreds = 0x00000080,
    [SDKName("ISC_REQ_ALLOCATE_MEMORY")]
    AllocateMemory = 0x00000100,
    [SDKName("ISC_REQ_USE_DCE_STYLE")]
    UseDCEStyle = 0x00000200,
    [SDKName("ISC_REQ_DATAGRAM")]
    Datagram = 0x00000400,
    [SDKName("ISC_REQ_CONNECTION")]
    Connection = 0x00000800,
    [SDKName("ISC_REQ_CALL_LEVEL")]
    CallLevel = 0x00001000,
    [SDKName("ISC_REQ_FRAGMENT_SUPPLIED")]
    FragmentSupplied = 0x00002000,
    [SDKName("ISC_REQ_EXTENDED_ERROR")]
    ExtendedError = 0x00004000,
    [SDKName("ISC_REQ_STREAM")]
    Stream = 0x00008000,
    [SDKName("ISC_REQ_INTEGRITY")]
    Integrity = 0x00010000,
    [SDKName("ISC_REQ_IDENTIFY")]
    Identify = 0x00020000,
    [SDKName("ISC_REQ_NULL_SESSION")]
    NullSession = 0x00040000,
    [SDKName("ISC_REQ_MANUAL_CRED_VALIDATION")]
    ManualCredValidation = 0x00080000,
    [SDKName("ISC_REQ_RESERVED1")]
    Reserved1 = 0x00100000,
    [SDKName("ISC_REQ_FRAGMENT_TO_FIT")]
    FragmentToFit = 0x00200000,
    [SDKName("ISC_REQ_FORWARD_CREDENTIALS")]
    ForwardCredentials = 0x00400000,
    [SDKName("ISC_REQ_NO_INTEGRITY")]
    NoIntegrity = 0x00800000,
    [SDKName("ISC_REQ_USE_HTTP_STYLE")]
    UseHttpStyle = 0x01000000,
    [SDKName("ISC_REQ_UNVERIFIED_TARGET_NAME")]
    UnverifiedTargetName = 0x20000000,
    [SDKName("ISC_REQ_CONFIDENTIALITY_ONLY")]
    ConfidentialityOnly = 0x40000000,
}

/// <summary>
/// Initialize context return flags.
/// </summary>
[Flags]
public enum InitializeContextRetFlags
{
    None = 0,
    [SDKName("ISC_RET_DELEGATE")]
    Delegate = 0x00000001,
    [SDKName("ISC_RET_MUTUAL_AUTH")]
    MutualAuth = 0x00000002,
    [SDKName("ISC_RET_REPLAY_DETECT")]
    ReplayDetect = 0x00000004,
    [SDKName("ISC_RET_SEQUENCE_DETECT")]
    SequenceDetect = 0x00000008,
    [SDKName("ISC_RET_CONFIDENTIALITY")]
    Confidentiality = 0x00000010,
    [SDKName("ISC_RET_USE_SESSION_KEY")]
    UseSessionKey = 0x00000020,
    [SDKName("ISC_RET_USED_COLLECTED_CREDS")]
    UsedCollectedCreds = 0x00000040,
    [SDKName("ISC_RET_USED_SUPPLIED_CREDS")]
    UsedSuppliedCreds = 0x00000080,
    [SDKName("ISC_RET_ALLOCATED_MEMORY")]
    AllocatedMemory = 0x00000100,
    [SDKName("ISC_RET_USED_DCE_STYLE")]
    UsedDceStyle = 0x00000200,
    [SDKName("ISC_RET_DATAGRAM")]
    Datagram = 0x00000400,
    [SDKName("ISC_RET_CONNECTION")]
    Connection = 0x00000800,
    [SDKName("ISC_RET_INTERMEDIATE_RETURN")]
    IntermediateReturn = 0x00001000,
    [SDKName("ISC_RET_CALL_LEVEL")]
    CallLevel = 0x00002000,
    [SDKName("ISC_RET_EXTENDED_ERROR")]
    ExtendedError = 0x00004000,
    [SDKName("ISC_RET_STREAM")]
    Stream = 0x00008000,
    [SDKName("ISC_RET_INTEGRITY")]
    Integrity = 0x00010000,
    [SDKName("ISC_RET_IDENTIFY")]
    Identify = 0x00020000,
    [SDKName("ISC_RET_NULL_SESSION")]
    NullSession = 0x00040000,
    [SDKName("ISC_RET_MANUAL_CRED_VALIDATION")]
    ManualCredValidation = 0x00080000,
    [SDKName("ISC_RET_RESERVED1")]
    Reserved1 = 0x00100000,
    [SDKName("ISC_RET_FRAGMENT_ONLY")]
    FragmentOnly = 0x00200000,
    [SDKName("ISC_RET_FORWARD_CREDENTIALS")]
    ForwardCredentials = 0x00400000,
    [SDKName("ISC_RET_USED_HTTP_STYLE")]
    UsedHttpStyle = 0x01000000,
    [SDKName("ISC_RET_NO_ADDITIONAL_TOKEN")]
    NoAdditionalToken = 0x02000000,
    [SDKName("ISC_RET_REAUTHENTICATION")]
    Reauthentication = 0x08000000,
    [SDKName("ISC_RET_CONFIDENTIALITY_ONLY")]
    ConfidentialityOnly = 0x40000000,
}

/// <summary>
/// Access context request flags.
/// </summary>
[Flags]
public enum AcceptContextReqFlags
{
    None = 0,
    [SDKName("ASC_REQ_DELEGATE")]
    Delegate = 0x00000001,
    [SDKName("ASC_REQ_MUTUAL_AUTH")]
    MutualAuth = 0x00000002,
    [SDKName("ASC_REQ_REPLAY_DETECT")]
    ReplayDetect = 0x00000004,
    [SDKName("ASC_REQ_SEQUENCE_DETECT")]
    SequenceDetect = 0x00000008,
    [SDKName("ASC_REQ_CONFIDENTIALITY")]
    Confidentiality = 0x00000010,
    [SDKName("ASC_REQ_USE_SESSION_KEY")]
    UseSessionKey = 0x00000020,
    [SDKName("ASC_REQ_SESSION_TICKET")]
    SessionTicket = 0x00000040,
    [SDKName("ASC_REQ_ALLOCATE_MEMORY")]
    AllocateMemory = 0x00000100,
    [SDKName("ASC_REQ_USE_DCE_STYLE")]
    UseDceStyle = 0x00000200,
    [SDKName("ASC_REQ_DATAGRAM")]
    Datagram = 0x00000400,
    [SDKName("ASC_REQ_CONNECTION")]
    Connection = 0x00000800,
    [SDKName("ASC_REQ_CALL_LEVEL")]
    CallLevel = 0x00001000,
    [SDKName("ASC_REQ_FRAGMENT_SUPPLIED")]
    FragmentSupplied = 0x00002000,
    [SDKName("ASC_REQ_EXTENDED_ERROR")]
    ExtendedError = 0x00008000,
    [SDKName("ASC_REQ_STREAM")]
    Stream = 0x00010000,
    [SDKName("ASC_REQ_INTEGRITY")]
    Integrity = 0x00020000,
    [SDKName("ASC_REQ_LICENSING")]
    Licensing = 0x00040000,
    [SDKName("ASC_REQ_IDENTIFY")]
    Identify = 0x00080000,
    [SDKName("ASC_REQ_ALLOW_NULL_SESSION")]
    AllowNullSessions = 0x00100000,
    [SDKName("ASC_REQ_ALLOW_NON_USER_LOGONS")]
    AllowNonUserLogons = 0x00200000,
    [SDKName("ASC_REQ_ALLOW_CONTEXT_REPLAY")]
    AllowContextReplay = 0x00400000,
    [SDKName("ASC_REQ_FRAGMENT_TO_FIT")]
    FragmentToFit = 0x00800000,
    [SDKName("ASC_REQ_NO_TOKEN")]
    NoToken = 0x01000000,
    [SDKName("ASC_REQ_PROXY_BINDINGS")]
    ProxyBindings = 0x04000000,
    [SDKName("ASC_REQ_ALLOW_MISSING_BINDINGS")]
    AllowMissingBindings = 0x10000000
}

/// <summary>
/// Accept context return flags.
/// </summary>
[Flags]
public enum AcceptContextRetFlags
{
    None = 0,
    [SDKName("ASC_RET_DELEGATE")]
    Delegate = 0x00000001,
    [SDKName("ASC_RET_MUTUAL_AUTH")]
    MutualAuth = 0x00000002,
    [SDKName("ASC_RET_REPLAY_DETECT")]
    ReplayDetect = 0x00000004,
    [SDKName("ASC_RET_SEQUENCE_DETECT")]
    SequenceDetect = 0x00000008,
    [SDKName("ASC_RET_CONFIDENTIALITY")]
    Confidentiality = 0x00000010,
    [SDKName("ASC_RET_USE_SESSION_KEY")]
    UseSessionKey = 0x00000020,
    [SDKName("ASC_RET_SESSION_TICKET")]
    SessionTicket = 0x00000040,
    [SDKName("ASC_RET_ALLOCATED_MEMORY")]
    AllocatedMemory = 0x00000100,
    [SDKName("ASC_RET_USED_DCE_STYLE")]
    UsedDceStyle = 0x00000200,
    [SDKName("ASC_RET_DATAGRAM")]
    Datagram = 0x00000400,
    [SDKName("ASC_RET_CONNECTION")]
    Connection = 0x00000800,
    [SDKName("ASC_RET_CALL_LEVEL")]
    CallLevel = 0x00002000,
    [SDKName("ASC_RET_THIRD_LEG_FAILED")]
    ThirdLegFailed = 0x00004000,
    [SDKName("ASC_RET_EXTENDED_ERROR")]
    ExtendedError = 0x00008000,
    [SDKName("ASC_RET_STREAM")]
    Stream = 0x00010000,
    [SDKName("ASC_RET_INTEGRITY")]
    Integrity = 0x00020000,
    [SDKName("ASC_RET_LICENSING")]
    Licensing = 0x00040000,
    [SDKName("ASC_RET_IDENTIFY")]
    Identify = 0x00080000,
    [SDKName("ASC_RET_NULL_SESSION")]
    NullSession = 0x00100000,
    [SDKName("ASC_RET_ALLOW_NON_USER_LOGONS")]
    AllowNonUserLogons = 0x00200000,
    [SDKName("ASC_RET_ALLOW_CONTEXT_REPLAY")]
    AllowContextReplay = 0x00400000,
    [SDKName("ASC_RET_FRAGMENT_ONLY")]
    FragmentOnly = 0x00800000,
    [SDKName("ASC_RET_NO_TOKEN")]
    NoToken = 0x01000000,
    [SDKName("ASC_RET_NO_ADDITIONAL_TOKEN")]
    NoAdditionalToken = 0x02000000,
}

/// <summary>
/// Security package capability flags.
/// </summary>
[Flags]
public enum SecPkgCapabilityFlag
{
    None = 0,
    /// <summary>
    /// Supports integrity on messages
    /// </summary>
    [SDKName("SECPKG_FLAG_INTEGRITY")]
    Integrity = 0x00000001,
    /// <summary>
    /// Supports privacy (confidentiality)
    /// </summary>
    [SDKName("SECPKG_FLAG_PRIVACY")]
    Privacy = 0x00000002,
    /// <summary>
    /// Only security token needed
    /// </summary>
    [SDKName("SECPKG_FLAG_TOKEN_ONLY")]
    TokenOnly = 0x00000004,
    /// <summary>
    /// Datagram RPC support
    /// </summary>
    [SDKName("SECPKG_FLAG_DATAGRAM")]
    Datagram = 0x00000008,
    /// <summary>
    /// Connection oriented RPC support
    /// </summary>
    [SDKName("SECPKG_FLAG_CONNECTION")]
    Connection = 0x00000010,
    /// <summary>
    /// Full 3-leg required for re-auth.
    /// </summary>
    [SDKName("SECPKG_FLAG_MULTI_REQUIRED")]
    MultiRequired = 0x00000020,
    /// <summary>
    /// Server side functionality not available
    /// </summary>
    [SDKName("SECPKG_FLAG_CLIENT_ONLY")]
    ClientOnly = 0x00000040,
    /// <summary>
    /// Supports extended error msgs
    /// </summary>
    [SDKName("SECPKG_FLAG_EXTENDED_ERROR")]
    ExtendedError = 0x00000080,
    /// <summary>
    /// Supports impersonation
    /// </summary>
    [SDKName("SECPKG_FLAG_IMPERSONATION")]
    Impersonation = 0x00000100,
    /// <summary>
    /// Accepts Win32 names
    /// </summary>
    [SDKName("SECPKG_FLAG_ACCEPT_WIN32_NAME")]
    AcceptWin32Name = 0x00000200,
    /// <summary>
    /// Supports stream semantics
    /// </summary>
    [SDKName("SECPKG_FLAG_STREAM")]
    Stream = 0x00000400,
    /// <summary>
    /// Can be used by the negotiate package
    /// </summary>
    [SDKName("SECPKG_FLAG_NEGOTIABLE")]
    Negotiable = 0x00000800,
    /// <summary>
    /// GSS Compatibility Available
    /// </summary>
    [SDKName("SECPKG_FLAG_GSS_COMPATIBLE")]
    GssCompatible = 0x00001000,
    /// <summary>
    /// Supports common LsaLogonUser
    /// </summary>
    [SDKName("SECPKG_FLAG_LOGON")]
    Logon = 0x00002000,
    /// <summary>
    /// Token Buffers are in ASCII
    /// </summary>
    [SDKName("SECPKG_FLAG_ASCII_BUFFERS")]
    AsciiBuffers = 0x00004000,
    /// <summary>
    /// Package can fragment to fit
    /// </summary>
    [SDKName("SECPKG_FLAG_FRAGMENT")]
    Fragment = 0x00008000,
    /// <summary>
    /// Package can perform mutual authentication
    /// </summary>
    [SDKName("SECPKG_FLAG_MUTUAL_AUTH")]
    MutualAuth = 0x00010000,
    /// <summary>
    /// Package can delegate
    /// </summary>
    [SDKName("SECPKG_FLAG_DELEGATION")]
    Delegation = 0x00020000,
    /// <summary>
    /// Supports integrity readonly checksum buffers.
    /// </summary>
    [SDKName("SECPKG_FLAG_READONLY_WITH_CHECKSUM")]
    ReadOnlyWithChecksum = 0x00040000,
    /// <summary>
    /// Package supports restricted callers
    /// </summary>
    [SDKName("SECPKG_FLAG_RESTRICTED_TOKENS")]
    RestrictedTokens = 0x00080000,
    /// <summary>
    /// This package extends SPNEGO, there is at most one
    /// </summary>
    [SDKName("SECPKG_FLAG_NEGO_EXTENDER")]
    NegoExtended = 0x00100000,
    /// <summary>
    /// This package is negotiated under the NegoExtender
    /// </summary>
    [SDKName("SECPKG_FLAG_NEGOTIABLE2")]
    Negotiable2 = 0x00200000,
    /// <summary>
    /// This package receives all calls from appcontainer apps
    /// </summary>
    [SDKName("SECPKG_FLAG_APPCONTAINER_PASSTHROUGH")]
    AppContainerPassthrough = 0x00400000,
    /// <summary>
    /// this package receives calls from appcontainer apps
    /// if the following checks succeed
    /// 1. Caller has domain auth capability or
    /// 2. Target is a proxy server or
    /// 3. The caller has supplied creds
    /// </summary>
    [SDKName("SECPKG_FLAG_APPCONTAINER_CHECKS")]
    AppContainerChecks = 0x00800000,
    /// <summary>
    /// This package is running with Credential Guard enabled
    /// </summary>
    [SDKName("SECPKG_FLAG_CREDENTIAL_ISOLATION_ENABLED")]
    CredentialIsolationEnabled = 0x01000000,
    /// <summary>
    /// this package supports reliable detection of loopback
    /// 1.) The client and server see the same sequence of tokens
    /// 2.) The server enforces a unique exchange for each
    ///     non-anonymous authentication. (Replay detection)
    /// </summary>
    [SDKName("SECPKG_FLAG_APPLY_LOOPBACK")]
    ApplyLoopback = 0x02000000,
}
