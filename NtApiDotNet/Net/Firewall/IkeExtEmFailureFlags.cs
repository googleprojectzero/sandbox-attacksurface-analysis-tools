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
using System;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// IKEEXT EM failure flags.
    /// </summary>
    [Flags]
    public enum IkeExtEmFailureFlags
    {
        None = 0,
        /// <summary>
        /// Flag indicating that multiple IKE EM failure events have been reported that
        /// should be correlated using the mmId field.
        /// </summary>
        [SDKName("FWPM_NET_EVENT_IKEEXT_EM_FAILURE_FLAG_MULTIPLE")]
        Multiple = 0x00000001,
        /// <summary>
        /// Flag indicating that the IKE EM failure event is a benign/expected failure
        /// </summary>
        [SDKName("FWPM_NET_EVENT_IKEEXT_EM_FAILURE_FLAG_BENIGN")]
        Benign = 0x00000002
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member