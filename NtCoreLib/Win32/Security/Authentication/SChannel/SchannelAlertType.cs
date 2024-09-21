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

namespace NtApiDotNet.Win32.Security.Authentication.Schannel
{
    /// <summary>
    /// Schannel Alert Type.
    /// </summary>
    public enum SchannelAlertType
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("TLS1_ALERT_WARNING")]
        Warning = 1,
        [SDKName("TLS1_ALERT_FATAL")]
        Fatal = 2,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
