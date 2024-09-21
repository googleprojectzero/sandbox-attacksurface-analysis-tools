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

namespace NtCoreLib.Win32.SideBySide.Parser;

/// <summary>
/// Class to represent an activation context COM ProgID redirection.
/// </summary>
public sealed class ActivationContextDataComProgIdRedirection
{
    /// <summary>
    /// The ProgID name.
    /// </summary>
    public string ProgId { get; }

    /// <summary>
    /// The associated CLSID.
    /// </summary>
    public Guid Clsid { get; }

    /// <summary>
    /// The assembly roster entry.
    /// </summary>
    public ActivationContextDataAssemblyRoster AssemblyRoster { get; }

    internal ActivationContextDataComProgIdRedirection(StringSectionEntry<ACTIVATION_CONTEXT_DATA_COM_PROGID_REDIRECTION> entry, SafeBufferGeneric handle, int base_offset)
    {
        ProgId = entry.Key;
        Clsid = handle.ReadStruct<Guid>(base_offset + entry.Entry.ConfiguredClsidOffset);
        AssemblyRoster = entry.RosterEntry;
    }
}
