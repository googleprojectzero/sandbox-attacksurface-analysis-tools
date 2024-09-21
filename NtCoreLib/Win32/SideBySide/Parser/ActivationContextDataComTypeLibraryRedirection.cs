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
using System;
using System.IO;

namespace NtCoreLib.Win32.SideBySide.Parser;

/// <summary>
/// Class to represent an activation context COM type library redirection
/// </summary>
public sealed class ActivationContextDataComTypeLibraryRedirection
{
    /// <summary>
    /// The type library ID.
    /// </summary>
    public Guid TypeLibraryId { get; }

    /// <summary>
    /// The type library name.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// The help directory.
    /// </summary>
    public string HelpDir { get; }

    /// <summary>
    /// The version.
    /// </summary>
    public Version Version { get; }

    /// <summary>
    /// The resource ID.
    /// </summary>
    public int ResourceId { get; }

    /// <summary>
    /// The library flags.
    /// </summary>
    public System.Runtime.InteropServices.ComTypes.LIBFLAGS LibraryFlags { get; }

    /// <summary>
    /// The full path to the library.
    /// </summary>
    public string FullPath { get; }

    /// <summary>
    /// The assembly roster entry.
    /// </summary>
    public ActivationContextDataAssemblyRoster AssemblyRoster { get; }

    internal ActivationContextDataComTypeLibraryRedirection(GuidSectionEntry<ACTIVATION_CONTEXT_DATA_COM_TYPE_LIBRARY_REDIRECTION> entry, SafeBufferGeneric handle, int base_offset)
    {
        TypeLibraryId = entry.Key;
        var ent = entry.Entry;
        Name = handle.ReadString(base_offset + ent.NameOffset, ent.NameLength);
        HelpDir = handle.ReadString(entry.Offset + ent.HelpDirOffset, ent.HelpDirLength);
        LibraryFlags = (System.Runtime.InteropServices.ComTypes.LIBFLAGS)ent.LibraryFlags;
        ResourceId = ent.ResourceId;
        Version = new Version(ent.MajorVersion, ent.MinorVersion);
        if (!string.IsNullOrWhiteSpace(entry.RosterEntry.FullPath))
        {
            FullPath = Path.Combine(entry.RosterEntry.FullPath);
        }
        else
        {
            FullPath = Name;
        }
        AssemblyRoster = entry.RosterEntry;
    }
}
