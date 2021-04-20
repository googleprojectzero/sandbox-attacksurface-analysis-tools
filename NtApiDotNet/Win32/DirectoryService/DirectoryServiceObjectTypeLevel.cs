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

namespace NtApiDotNet.Win32.DirectoryService
{
    /// <summary>
    /// Object type level for a directory object.
    /// </summary>
    public enum DirectoryServiceObjectTypeLevel
    {
        /// <summary>
        /// Object type.
        /// </summary>
        [SDKName("ACCESS_OBJECT_GUID")]
        Object = 0,
        /// <summary>
        /// Property set type.
        /// </summary>
        [SDKName("ACCESS_PROPERTY_SET_GUID")]
        PropertySet = 1,
        /// <summary>
        /// Property type.
        /// </summary>
        [SDKName("ACCESS_PROPERTY_GUID")]
        Property = 2,
    }
}
