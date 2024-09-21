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
    public enum FirewallActionType : uint
    {
        [SDKName("FWP_ACTION_FLAG_TERMINATING")]
        Terminating = 0x00001000,
        [SDKName("FWP_ACTION_BLOCK")]
        Block = 0x00000001 | Terminating,
        [SDKName("FWP_ACTION_PERMIT")]
        Permit = 0x00000002 | Terminating,
        [SDKName("FWP_ACTION_CALLOUT_TERMINATING")]
        CalloutTerminating = 0x00000003 | Callout | Terminating,
        [SDKName("FWP_ACTION_CALLOUT_INSPECTION")]
        CalloutInspection = 0x00000004 | Callout | NonTerminating,
        [SDKName("FWP_ACTION_CALLOUT_UNKNOWN")]
        CalloutUnknown = 0x00000005 | Callout,
        [SDKName("FWP_ACTION_CONTINUE")]
        Continue = 0x00000006 | NonTerminating,
        [SDKName("FWP_ACTION_NONE")]
        None = 0x00000007,
        [SDKName("FWP_ACTION_NONE_NO_MATCH")]
        NoneNoMatch = 0x00000008,
        [SDKName("FWP_ACTION_BITMAP_INDEX_SET")]
        BitmapIndexSet = 0x00000009,
        [SDKName("FWP_ACTION_FLAG_NON_TERMINATING")]
        NonTerminating = 0x00002000,
        [SDKName("FWP_ACTION_FLAG_CALLOUT")]
        Callout = 0x00004000,
        All = 0xFFFFFFFF
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member