//  Copyright 2016 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Security.Token;

#pragma warning disable 1591
[SDKName("SECURITY_CONTEXT_TRACKING_MODE")]
public enum SecurityContextTrackingMode : byte
{
    [SDKName("SECURITY_STATIC_TRACKING")]
    Static = 0,
    [SDKName("SECURITY_DYNAMIC_TRACKING")]
    Dynamic = 1
}
#pragma warning restore 1591

