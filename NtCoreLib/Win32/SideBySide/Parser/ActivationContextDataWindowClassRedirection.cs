//  Copyright 2023 Google LLC. All Rights Reserved.
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
//
//  Note this is relicensed from OleViewDotNet by the author.

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Win32.SideBySide.Interop;

namespace NtCoreLib.Win32.SideBySide.Parser;

/// <summary>
/// Class to represent an activation context window class redirection.
/// </summary>
public sealed class ActivationContextDataWindowClassRedirection
{
    /// <summary>
    /// The window class name.
    /// </summary>
    public string VersionSpecificClassName { get; }

    /// <summary>
    /// The name of the DLL containing the class.
    /// </summary>
    public string DllName { get; }

    /// <summary>
    /// The assembly roster entry.
    /// </summary>
    public ActivationContextDataAssemblyRoster AssemblyRoster { get; }

    internal ActivationContextDataWindowClassRedirection(StringSectionEntry<ACTIVATION_CONTEXT_DATA_WINDOW_CLASS_REDIRECTION> entry, SafeBufferGeneric handle, int base_offset)
    {
        VersionSpecificClassName = handle.ReadString(entry.Offset + entry.Entry.VersionSpecificClassNameOffset, entry.Entry.VersionSpecificClassNameLength);
        DllName = handle.ReadString(base_offset + entry.Entry.DllNameOffset, entry.Entry.DllNameLength);
        AssemblyRoster = entry.RosterEntry;
    }
}