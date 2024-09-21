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

namespace NtCoreLib.Security.Authorization;

/// <summary>
/// Predefined security authorities
/// </summary>
public enum SecurityAuthority : byte
{
#pragma warning disable 1591
    Null = 0,
    World = 1,
    Local = 2,
    Creator = 3,
    NonUnique = 4,
    Nt = 5,
    ResourceManager = 9,
    Package = 15,
    Label = 16,
    ScopedPolicyId = 17,
    Authentication = 18,
    ProcessTrust = 19,
#pragma warning restore 1591
}
