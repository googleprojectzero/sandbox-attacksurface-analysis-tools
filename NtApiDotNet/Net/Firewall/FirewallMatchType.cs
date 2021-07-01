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
    /// Firewall filter match type.
    /// </summary>
    public enum FirewallMatchType
    {
        [SDKName("FWP_MATCH_EQUAL")]
        Equal = 0,
        [SDKName("FWP_MATCH_GREATER")]
        Greater = Equal + 1,
        [SDKName("FWP_MATCH_LESS")]
        Less = Greater + 1,
        [SDKName("FWP_MATCH_GREATER_OR_EQUAL")]
        GreaterOrEqual = Less + 1,
        [SDKName("FWP_MATCH_LESS_OR_EQUAL")]
        LessOrEqual = GreaterOrEqual + 1,
        [SDKName("FWP_MATCH_RANGE")]
        Range = LessOrEqual + 1,
        [SDKName("FWP_MATCH_FLAGS_ALL_SET")]
        FlagsAllSet = Range + 1,
        [SDKName("FWP_MATCH_FLAGS_ANY_SET")]
        FlagsAnySet = FlagsAllSet + 1,
        [SDKName("FWP_MATCH_FLAGS_NONE_SET")]
        FlagsNoneSet = FlagsAnySet + 1,
        [SDKName("FWP_MATCH_EQUAL_CASE_INSENSITIVE")]
        EqualCaseInsensitive = FlagsNoneSet + 1,
        [SDKName("FWP_MATCH_NOT_EQUAL")]
        NotEqual = EqualCaseInsensitive + 1,
        [SDKName("FWP_MATCH_PREFIX")]
        Prefix = NotEqual + 1,
        [SDKName("FWP_MATCH_NOT_PREFIX")]
        NotPrefix = Prefix + 1
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member