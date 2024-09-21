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

namespace NtCoreLib.Security.Authorization;

/// <summary>
/// Source for a SID name.
/// </summary>
public enum SidNameSource
{
    /// <summary>
    /// SDDL string.
    /// </summary>
    Sddl,
    /// <summary>
    /// LSASS lookup.
    /// </summary>
    Account,
    /// <summary>
    /// Named capability.
    /// </summary>
    Capability,
    /// <summary>
    /// Package name SID.
    /// </summary>
    Package,
    /// <summary>
    /// From a process trust level.
    /// </summary>
    ProcessTrust,
    /// <summary>
    /// Well known SID.
    /// </summary>
    WellKnown,
    /// <summary>
    /// Scoped policy SID.
    /// </summary>
    ScopedPolicyId,
    /// <summary>
    /// Manually added name.
    /// </summary>
    Manual
}
