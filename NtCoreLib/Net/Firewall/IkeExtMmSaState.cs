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
/// IKE main mode states
/// </summary>
[SDKName("IKEEXT_MM_SA_STATE")]
public enum IkeExtMmSaState
{
    /// <summary>
    /// Initial state. No MM packets have been sent to the peer yet.
    /// </summary>
    [SDKName("IKEEXT_MM_SA_STATE_NONE")]
    None,
    /// <summary>
    /// First roundtrip packet has been sent to the peer. 
    /// </summary>
    [SDKName("IKEEXT_MM_SA_STATE_SA_SENT")]
    SaSent,
    /// <summary>
    /// Second roundtrip packet has been sent to the peer, for SSPI auth.
    /// </summary>
    [SDKName("IKEEXT_MM_SA_STATE_SSPI_SENT")]
    SspiSent,
    /// <summary>
    /// Second roundtrip packet has been sent to the peer.
    /// </summary>
    [SDKName("IKEEXT_MM_SA_STATE_FINAL")]
    Final,
    /// <summary>
    /// Final roundtrip packet has been sent to the peer.
    /// </summary>
    [SDKName("IKEEXT_MM_SA_STATE_FINAL_SENT")]
    FinalSent,
    /// <summary>
    /// MM has been completed.
    /// </summary>
    [SDKName("IKEEXT_MM_SA_STATE_COMPLETE")]
    Complete,
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member