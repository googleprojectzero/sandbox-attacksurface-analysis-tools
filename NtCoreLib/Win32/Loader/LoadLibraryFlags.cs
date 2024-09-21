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

using NtCoreLib.Utilities.Reflection;
using System;

namespace NtCoreLib.Win32.Loader;

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
    [SDKName("DONT_RESOLVE_DLL_REFERENCES")]
    DontResolveDllReferences = 0x00000001,
    /// <summary>
    /// Load library as a data file.
    /// </summary>
    [SDKName("LOAD_LIBRARY_AS_DATAFILE")]
    AsDataFile = 0x00000002,
    /// <summary>
    /// Load packed library.i
    /// </summary>
    [SDKName("LOAD_PACKAGED_LIBRARY")]
    PackedLibrary = 0x00000004,
    /// <summary>
    /// Load with an altered search path.
    /// </summary>
    [SDKName("LOAD_WITH_ALTERED_SEARCH_PATH")]
    WithAlteredSearchPath = 0x00000008,
    /// <summary>
    /// Ignore code authz level.
    /// </summary>
    [SDKName("LOAD_IGNORE_CODE_AUTHZ_LEVEL")]
    IgnoreCodeAuthzLevel = 0x00000010,
    /// <summary>
    /// Load library as an image resource.
    /// </summary>
    [SDKName("LOAD_LIBRARY_AS_IMAGE_RESOURCE")]
    AsImageResource = 0x00000020,
    /// <summary>
    /// Load library as a data file exclusively.
    /// </summary>
    [SDKName("LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE")]
    AsDataFileExclusive = 0x00000040,
    /// <summary>
    /// Require library is a signed file.
    /// </summary>
    [SDKName("LOAD_LIBRARY_REQUIRE_SIGNED_TARGET")]
    RequiredSignedTarget = 0x00000080,
    /// <summary>
    /// Add the DLL's directory temporarily to the search list.
    /// </summary>
    [SDKName("LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR")]
    SearchDllLoadDir = 0x00000100,
    /// <summary>
    /// Search application directory for the DLL.
    /// </summary>
    [SDKName("LOAD_LIBRARY_SEARCH_APPLICATION_DIR")]
    SearchApplicationDir = 0x00000200,
    /// <summary>
    /// Search the user's directories for the DLL.
    /// </summary>
    [SDKName("LOAD_LIBRARY_SEARCH_USER_DIRS")]
    SearchUserDirs = 0x00000400,
    /// <summary>
    /// Search system32 for the DLL.
    /// </summary>
    [SDKName("LOAD_LIBRARY_SEARCH_SYSTEM32")]
    SearchSystem32 = 0x00000800,
    /// <summary>
    /// Search the default directories for the DLL.
    /// </summary>
    [SDKName("LOAD_LIBRARY_SEARCH_DEFAULT_DIRS")]
    SearchDefaultDirs = 0x00001000,
    /// <summary>
    /// Safe current dirs.
    /// </summary>
    [SDKName("LOAD_LIBRARY_SAFE_CURRENT_DIRS")]
    SafeCurrentDirs = 0x00002000,
    /// <summary>
    /// Search system32 with no forwarder.
    /// </summary>
    [SDKName("LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER")]
    SearchSystem32NoForwarder = 0x00004000,
    /// <summary>
    /// OS integrity continuity.
    /// </summary>
    [SDKName("LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY")]
    OsIntegrityContinuity = 0x00008000,
}
