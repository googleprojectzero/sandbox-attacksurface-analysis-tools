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
/// Class to represent an activation context COM server redirection.
/// </summary>
public sealed class ActivationContextDataComServerRedirection
{
    /// <summary>
    /// The server CLSID.
    /// </summary>
    public Guid Clsid { get; }

    /// <summary>
    /// Reference CLSID.
    /// </summary>
    public Guid ReferenceClsid { get; }

    /// <summary>
    /// Configured CLSID.
    /// </summary>
    public Guid ConfiguredClsid { get; }

    /// <summary>
    /// Implemented CLSID.
    /// </summary>
    public Guid ImplementedClsid { get; }

    /// <summary>
    /// Type library ID.
    /// </summary>
    public Guid TypeLibraryId { get; }

    /// <summary>
    /// Module name.
    /// </summary>
    public string Module { get; }

    /// <summary>
    /// Full path to the module.
    /// </summary>
    public string FullPath { get; }

    /// <summary>
    /// ProgID of the server.
    /// </summary>
    public string ProgId { get; }

    /// <summary>
    /// COM threading model.
    /// </summary>
    public ActivationContextDataComServerRedirectionThreadingModel ThreadingModel { get; }

    /// <summary>
    /// The assembly roster entry.
    /// </summary>
    public ActivationContextDataAssemblyRoster AssemblyRoster { get; }

    internal ActivationContextDataComServerRedirection(GuidSectionEntry<ACTIVATION_CONTEXT_DATA_COM_SERVER_REDIRECTION> entry, SafeBufferGeneric handle, int base_offset, int struct_offset)
    {
        Clsid = entry.Key;
        ReferenceClsid = entry.Entry.ReferenceClsid;
        ConfiguredClsid = entry.Entry.ConfiguredClsid;
        ImplementedClsid = entry.Entry.ImplementedClsid;
        TypeLibraryId = entry.Entry.TypeLibraryId;
        Module = handle.ReadString(base_offset + entry.Entry.ModuleOffset, entry.Entry.ModuleLength);
        ProgId = handle.ReadString(struct_offset + entry.Entry.ProgIdOffset, entry.Entry.ProgIdLength);
        ThreadingModel = entry.Entry.ThreadingModel;
        if (!string.IsNullOrWhiteSpace(entry.RosterEntry.FullPath))
        {
            FullPath = Path.Combine(entry.RosterEntry.FullPath, Module);
        }
        else
        {
            FullPath = Module;
        }
        AssemblyRoster = entry.RosterEntry;
    }
}
