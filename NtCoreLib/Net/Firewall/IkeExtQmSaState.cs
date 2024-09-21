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

using NtApiDotNet.Utilities.Reflection;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// IKE quick mode states
    /// </summary>
    [SDKName("IKEEXT_QM_SA_STATE")]
    public enum IkeExtQmSaState
    {
        /// <summary>
        /// Initial state. No QM packets have been sent to the peer yet.
        /// </summary>
        [SDKName("IKEEXT_QM_SA_STATE_NONE")]
        None,
        /// <summary>
        /// State corresponding to the first QM roundtrip
        /// </summary>
        [SDKName("IKEEXT_QM_SA_STATE_INITIAL")]
        Initial,
        /// <summary>
        /// State corresponding to the final QM roundtrip
        /// </summary>
        [SDKName("IKEEXT_QM_SA_STATE_FINAL")]
        Final,
        /// <summary>
        /// QM has been completed.
        /// </summary>
        [SDKName("IKEEXT_QM_SA_STATE_COMPLETE")]
        Complete,
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member