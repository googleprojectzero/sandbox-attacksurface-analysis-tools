//  Copyright 2020 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Security.Authorization
{
#pragma warning disable 1591
    /// <summary>
    /// Tree security mode.
    /// </summary>
    public enum TreeSecInfo
    {
        Set = 1,
        Reset = 2,
        ResetKeepExplicit = 3
    }

    /// <summary>
    /// Progress function for tree named security info.
    /// </summary>
    /// <param name="object_name">The name of the object.</param>
    /// <param name="status">The operation status.</param>
    /// <param name="invoke_setting">The current invoke setting.</param>
    /// <param name="security_set">True if security is set.</param>
    /// <returns>The invoke setting. Return original invoke_setting if no change.</returns>
    public delegate ProgressInvokeSetting TreeProgressFunction(string object_name, Win32Error status,
        ProgressInvokeSetting invoke_setting, bool security_set);
}
