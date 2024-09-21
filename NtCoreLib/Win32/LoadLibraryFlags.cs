//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Flags for loading a library.
    /// </summary>
    [Flags]
    public enum LoadLibraryFlags
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Don't resolve DLL references
        /// </summary>
        DontResolveDllReferences = 0x00000001,
        /// <summary>
        /// Load library as a data file.
        /// </summary>
        LoadLibraryAsDataFile = 0x00000002,
        /// <summary>
        /// Load with an altered search path.
        /// </summary>
        LoadWithAlteredSearchPath = 0x00000008,
        /// <summary>
        /// Ignore code authz level.
        /// </summary>
        LoadIgnoreCodeAuthzLevel = 0x00000010,
        /// <summary>
        /// Load library as an image resource.
        /// </summary>
        LoadLibraryAsImageResource = 0x00000020,
        /// <summary>
        /// Load library as a data file exclusively.
        /// </summary>
        LoadLibraryAsDataFileExclusive = 0x00000040,
        /// <summary>
        /// Add the DLL's directory temporarily to the search list.
        /// </summary>
        LoadLibrarySearchDllLoadDir = 0x00000100,
        /// <summary>
        /// Search application directory for the DLL.
        /// </summary>
        LoadLibrarySearchApplicationDir = 0x00000200,
        /// <summary>
        /// Search the user's directories for the DLL.
        /// </summary>
        LoadLibrarySearchUserDirs = 0x00000400,
        /// <summary>
        /// Search system32 for the DLL.
        /// </summary>
        LoadLibrarySearchSystem32 = 0x00000800,
        /// <summary>
        /// Search the default directories for the DLL.
        /// </summary>
        LoadLibrarySearchDefaultDirs = 0x00001000,
    }
}
