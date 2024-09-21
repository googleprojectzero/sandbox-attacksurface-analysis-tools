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
using System.IO;
using System.Linq;

namespace NtCoreLib.Win32.SideBySide.Parser;

/// <summary>
/// Class to represent a DLL redirection entry.
/// </summary>
public sealed class ActivationContextDataDllRedirection
{
    /// <summary>
    /// The name of the DLL.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// The redirected path.
    /// </summary>
    public string FullPath { get; }

    /// <summary>
    /// The assembly roster entry.
    /// </summary>
    public ActivationContextDataAssemblyRoster AssemblyRoster { get; }

    /// <summary>
    /// The flags for the redirection.
    /// </summary>
    public ActivationContextDataDllRedirectionPathFlags Flags { get; }

    internal ActivationContextDataDllRedirection(StringSectionEntry<ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION> entry, SafeBufferGeneric handle, int base_offset)
    {
        Name = entry.Key;
        var paths = handle.ReadArray<ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT>(base_offset + entry.Entry.PathSegmentOffset,
            entry.Entry.PathSegmentCount).Select(e => handle.ReadString(base_offset + e.Offset, e.Length)).ToList();
        if (entry.Entry.Flags.HasFlagSet(ActivationContextDataDllRedirectionPathFlags.OmitsAssemblyRoot) && entry.RosterEntry != null)
        {
            paths.Insert(0, entry.RosterEntry.FullPath);
        }
        if (!entry.Entry.Flags.HasFlagSet(ActivationContextDataDllRedirectionPathFlags.IncludesBaseName))
        {
            paths.Add(Path.GetFileName(Name));
        }
        FullPath = Path.Combine(paths.ToArray());
        Flags = entry.Entry.Flags;
        AssemblyRoster = entry.RosterEntry;
    }
}
