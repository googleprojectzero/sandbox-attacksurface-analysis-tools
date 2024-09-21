//  Copyright 2021 Google LLC. All Rights Reserved.
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

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// IKE extended mode states
/// </summary>
[SDKName("IKEEXT_EM_SA_STATE")]
public enum IkeExtEmSaState
{
    /// <summary>
    /// Initial state. No EM packets have been sent to the peer yet.
    /// </summary>
    [SDKName("IKEEXT_EM_SA_STATE_NONE")]
    None,
    /// <summary>
    /// State corresponding to the first EM roundtrip
    /// </summary>
    [SDKName("IKEEXT_EM_SA_STATE_SENT_ATTS")]
    SentAtts,
    /// <summary>
    /// State corresponding to the second EM roundtrip
    /// </summary>
    [SDKName("IKEEXT_EM_SA_STATE_SSPI_SENT")]
    SspiSent,
    /// <summary>
    /// State corresponding to the final EM roundtrip
    /// </summary>
    [SDKName("IKEEXT_EM_SA_STATE_AUTH_COMPLETE")]
    AuthComplete,
    /// <summary>
    /// State corresponding to the final EM roundtrip
    /// </summary>
    [SDKName("IKEEXT_EM_SA_STATE_FINAL")]
    Final,
    /// <summary>
    /// EM has been completed
    /// </summary>
    [SDKName("IKEEXT_EM_SA_STATE_COMPLETE")]
    Complete,
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member