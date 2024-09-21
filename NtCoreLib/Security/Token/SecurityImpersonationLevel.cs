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

[SDKName("SECURITY_IMPERSONATION_LEVEL")]
public enum SecurityImpersonationLevel
{
    [SDKName("SecurityAnonymous")]
    Anonymous = 0,
    [SDKName("SecurityIdentification")]
    Identification = 1,
    [SDKName("SecurityImpersonation")]
    Impersonation = 2,
    [SDKName("SecurityDelegation")]
    Delegation = 3
}
#pragma warning restore 1591

