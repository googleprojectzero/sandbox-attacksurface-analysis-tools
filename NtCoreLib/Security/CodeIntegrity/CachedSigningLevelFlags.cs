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

using System;

namespace NtCoreLib.Security.CodeIntegrity;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Flags]
public enum CachedSigningLevelFlags
{
    None = 0,
    UntrustedSignature = 1,
    TrustedSignature = 2,
    Unknown4 = 4,
    DontUseUSNJournal = 8,
    HasPerAppRules = 0x10,
    SetInTestMode = 0x20,
    ProtectedLightVerification = 0x40
}

#pragma warning restore 1591

