//  Copyright 2017 Google Inc. All Rights Reserved.
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

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="description">Check mode for accessible services.</para>
/// </summary>
public enum ServiceCheckMode
{
    /// <summary>
    /// Only services.
    /// </summary>
    ServiceOnly,
    /// <summary>
    /// Only drivers.
    /// </summary>
    DriverOnly,
    /// <summary>
    /// Services and drivers.
    /// </summary>
    ServiceAndDriver
}
