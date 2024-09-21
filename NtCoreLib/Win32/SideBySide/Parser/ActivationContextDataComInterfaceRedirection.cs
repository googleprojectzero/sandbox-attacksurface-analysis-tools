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
/// Class to represent an activation context COM interface redirection.
/// </summary>
public sealed class ActivationContextDataComInterfaceRedirection
{
    /// <summary>
    /// The IID of the interface.
    /// </summary>
    public Guid Iid { get; }

    /// <summary>
    /// The proxy stub CLSID.
    /// </summary>
    public Guid ProxyStubClsid32 { get; }

    /// <summary>
    /// Number of methods.
    /// </summary>
    public int NumMethods { get; }

    /// <summary>
    /// Associated type library ID.
    /// </summary>
    public Guid TypeLibraryId { get; }

    /// <summary>
    /// The base interface type.
    /// </summary>
    public Guid BaseInterface { get; }

    /// <summary>
    /// The name of the interface.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// The assembly roster entry.
    /// </summary>
    public ActivationContextDataAssemblyRoster AssemblyRoster { get; }

    internal ActivationContextDataComInterfaceRedirection(GuidSectionEntry<ACTIVATION_CONTEXT_DATA_COM_INTERFACE_REDIRECTION> entry, SafeBufferGeneric handle, int base_offset)
    {
        Iid = entry.Key;
        var ent = entry.Entry;
        ProxyStubClsid32 = ent.ProxyStubClsid32;
        NumMethods = ent.NumMethods;
        TypeLibraryId = ent.TypeLibraryId;
        BaseInterface = ent.BaseInterface;
        Name = handle.ReadString(entry.Offset + ent.NameOffset, ent.NameLength);
        AssemblyRoster = entry.RosterEntry;
    }
}
