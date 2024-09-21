//  Copyright 2019 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Security.CodeIntegrity;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
public enum SigningLevel
{
    Unchecked = 0,
    Unsigned = 1,
    DeviceGuard = 2,
    Custom1 = 3,
    Authenticode = 4,
    Custom2 = 5,
    Store = 6,
    Antimalware = 7,
    Microsoft = 8,
    Custom4 = 9,
    Custom5 = 10,
    DynamicCodeGeneration = 11,
    Windows = 12,
    WindowsProtectedProcessLight = 13,
    WindowsTCB = 14,
    Custom6 = 15
}

#pragma warning restore 1591

