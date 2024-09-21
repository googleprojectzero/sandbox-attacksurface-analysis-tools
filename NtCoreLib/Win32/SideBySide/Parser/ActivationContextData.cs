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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.SideBySide.Parser;

/// <summary>
/// Class to represent a parsed activation context.
/// </summary>
public sealed class ActivationContextData
{
    const uint ACTCTX_MAGIC = 0x78746341;
    const int ACTCTX_VERSION = 1;
    const uint STRING_SECTION_MAGIC = 0x64487353;
    const uint GUID_SECTION_MAGIC = 0x64487347;

    private readonly List<ActivationContextDataAssemblyRoster> _asm_roster = new();

    /// <summary>
    /// List of assembly rosters.
    /// </summary>
    public IReadOnlyList<ActivationContextDataAssemblyRoster> AssemblyRosters => _asm_roster.Where(e => e.Flags != ActivationContextDataAssemblyRosterFlags.Invalid).ToList().AsReadOnly();

    /// <summary>
    /// List of COM server redirections.
    /// </summary>
    public IReadOnlyList<ActivationContextDataComServerRedirection> ComServers { get; }

    /// <summary>
    /// List of ProgID redirections.
    /// </summary>
    public IReadOnlyList<ActivationContextDataComProgIdRedirection> ComProgIds { get; }

    /// <summary>
    /// List of DLL redirections.
    /// </summary>
    public IReadOnlyList<ActivationContextDataDllRedirection> DllRedirection { get; }

    /// <summary>
    /// List of COM interface redirections.
    /// </summary>
    public IReadOnlyList<ActivationContextDataComInterfaceRedirection> ComInterfaces { get; }

    /// <summary>
    /// List of COM type library redirections.
    /// </summary>
    public IReadOnlyList<ActivationContextDataComTypeLibraryRedirection> ComTypeLibs { get; }

    /// <summary>
    /// List of application settings.
    /// </summary>
    public IReadOnlyList<ActivationContextDataApplicationSettings> ApplicationSettings { get; }

    /// <summary>
    /// List of window classes.
    /// </summary>
    public IReadOnlyList<ActivationContextDataWindowClassRedirection> WindowClasses { get; }

    private ActivationContextDataAssemblyRoster GetAssemblyRosterEntry(int index)
    {
        if (index < 0 || index >= _asm_roster.Count)
        {
            return _asm_roster[0];
        }
        return _asm_roster[index];
    }

    private IEnumerable<StringSectionEntry<T>> ReadStringSection<T>(SafeBufferGeneric handle, ACTIVATION_CONTEXT_DATA_TOC_ENTRY toc_entry) where T : struct
    {
        if (toc_entry.Format != ACTIVATION_CONTEXT_SECTION_FORMAT.STRING_TABLE || toc_entry.Length < Marshal.SizeOf<ACTIVATION_CONTEXT_STRING_SECTION_HEADER>())
        {
            throw new InvalidDataException("Expected string section in TOC.");
        }

        List<StringSectionEntry<T>> ret = new();

        int base_offset = toc_entry.Offset;
        
        var header = handle.ReadStruct<ACTIVATION_CONTEXT_STRING_SECTION_HEADER>(base_offset);
        if (header.Magic != STRING_SECTION_MAGIC || header.FormatVersion != 1)
        {
            throw new InvalidDataException("Invalid string section header.");
        }

        foreach (var entry in handle.ReadArray<ACTIVATION_CONTEXT_STRING_SECTION_ENTRY>(base_offset + header.ElementListOffset, header.ElementCount))
        {
            string key = handle.ReadString(base_offset + entry.KeyOffset, entry.KeyLength);
            T value = handle.ReadStruct<T>(base_offset + entry.Offset);
            ret.Add(new StringSectionEntry<T>(key, value, base_offset + entry.Offset, GetAssemblyRosterEntry(entry.AssemblyRosterIndex)));
        }

        return ret;
    }

    private IEnumerable<GuidSectionEntry<T>> ReadGuidSection<T>(SafeBufferGeneric handle, ACTIVATION_CONTEXT_DATA_TOC_ENTRY toc_entry) where T : struct
    {
        if (toc_entry.Format != ACTIVATION_CONTEXT_SECTION_FORMAT.GUID_TABLE || toc_entry.Length < Marshal.SizeOf<ACTIVATION_CONTEXT_GUID_SECTION_HEADER>())
        {
            throw new InvalidDataException("Expected GUID section in TOC.");
        }

        List<GuidSectionEntry<T>> ret = new();
        int base_offset = toc_entry.Offset;
        var header = handle.ReadStruct<ACTIVATION_CONTEXT_GUID_SECTION_HEADER>(base_offset);
        if (header.Magic != GUID_SECTION_MAGIC || header.FormatVersion != 1)
        {
            return ret;
        }

        foreach(var entry in handle.ReadArray<ACTIVATION_CONTEXT_GUID_SECTION_ENTRY>(base_offset + header.ElementListOffset, header.ElementCount))
        {
            T value = handle.ReadStruct<T>(base_offset + entry.Offset);
            ret.Add(new GuidSectionEntry<T>(entry.Guid, value, base_offset + entry.Offset, GetAssemblyRosterEntry(entry.AssemblyRosterIndex)));
        }
        return ret;
    }

    const int ACTCTX_PEB_OFFSET_32 = 0x1F8;
    const int ACTCTX_PEB_OFFSET_64 = 0x2F8;
    const int DEFAULT_ACTCTX_PEB_OFFSET_32 = 0x200;
    const int DEFAULT_ACTCTX_PEB_OFFSET_64 = 0x308;

    /// <summary>
    /// Read the activation context from the current process.
    /// </summary>
    /// <param name="default_actctx">True to read the default activation context.</param>
    /// <returns>The parsed activation context.</returns>
    public static ActivationContextData FromProcess(bool default_actctx = false)
    {
        return FromProcess(NtProcess.Current, default_actctx);
    }

    /// <summary>
    /// Read the activation context from a process.
    /// </summary>
    /// <param name="process">The process to read from.</param>
    /// <param name="default_actctx">True to read the default activation context.</param>
    /// <returns>The parsed activation context.</returns>
    public static ActivationContextData FromProcess(NtProcess process, bool default_actctx = false)
    {
        bool is_64bit = process.Is64Bit || Environment.Is64BitOperatingSystem;

        int offset;
        if (default_actctx)
        {
            offset = is_64bit ? DEFAULT_ACTCTX_PEB_OFFSET_64 : DEFAULT_ACTCTX_PEB_OFFSET_32;
        }
        else
        {
            offset = is_64bit ? ACTCTX_PEB_OFFSET_64 : ACTCTX_PEB_OFFSET_32;
        }

        long peb_base = process.PebAddress.ToInt64();
        long actctx_base;
        if (is_64bit)
        {
            actctx_base = process.ReadMemory<long>(peb_base + offset);
        }
        else
        {
            actctx_base = process.ReadMemory<uint>(peb_base + offset);
        }

        if (actctx_base == 0)
        {
            return null;
        }

        return FromProcess(process, actctx_base);
    }

    /// <summary>
    /// Read the activation context from a process.
    /// </summary>
    /// <param name="process">The process to read from.</param>
    /// <param name="actctx_base">The base address of the activation context.</param>
    /// <returns>The parsed activation context.</returns>
    public static ActivationContextData FromProcess(NtProcess process, long actctx_base)
    {
        var header = process.ReadMemory<ACTIVATION_CONTEXT_DATA>(actctx_base);
        if (header.Magic != ACTCTX_MAGIC && header.FormatVersion != ACTCTX_VERSION)
        {
            throw new InvalidDataException("Invalid activation context data header.");
        }

        return new ActivationContextData(process.ReadMemory(actctx_base, header.TotalSize));
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="actctx">The activation context as an array.</param>
    public ActivationContextData(byte[] actctx)
    {
        using var handle = actctx.ToBuffer();
        ACTIVATION_CONTEXT_DATA header = handle.Read<ACTIVATION_CONTEXT_DATA>(0);
        if (header.Magic != ACTCTX_MAGIC && header.FormatVersion != ACTCTX_VERSION)
        {
            throw new InvalidDataException("Invalid activation context data header.");
        }

        var roster_header = handle.Read<ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER>(header.AssemblyRosterOffset);
        _asm_roster.AddRange(handle.ReadArray<ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY>(roster_header.FirstEntryOffset, roster_header.EntryCount).Select(e => new ActivationContextDataAssemblyRoster(e, handle, roster_header.AssemblyInformationSectionOffset)));

        var toc_header = handle.Read<ACTIVATION_CONTEXT_DATA_TOC_HEADER>(header.DefaultTocOffset);

        var toc_entries = handle.ReadArray<ACTIVATION_CONTEXT_DATA_TOC_ENTRY>(toc_header.FirstEntryOffset, toc_header.EntryCount);

        foreach (var toc_entry in toc_entries)
        {
            switch (toc_entry.Id)
            {
                case ACTIVATION_CONTEXT_SECTION_ID.COM_PROGID_REDIRECTION:
                    ComProgIds = ReadStringSection<ACTIVATION_CONTEXT_DATA_COM_PROGID_REDIRECTION>(handle,
                        toc_entry).Select(e => new ActivationContextDataComProgIdRedirection(e, handle, toc_entry.Offset)).ToReadOnlyList();
                    break;
                case ACTIVATION_CONTEXT_SECTION_ID.DLL_REDIRECTION:
                    DllRedirection = ReadStringSection<ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION>(handle, toc_entry)
                        .Select(e => new ActivationContextDataDllRedirection(e, handle, toc_entry.Offset)).ToReadOnlyList();
                    break;
                case ACTIVATION_CONTEXT_SECTION_ID.APPLICATION_SETTINGS:
                    ApplicationSettings = ReadStringSection<ACTIVATION_CONTEXT_DATA_APPLICATION_SETTINGS>(handle, toc_entry)
                        .Select(e => new ActivationContextDataApplicationSettings(e, handle)).ToReadOnlyList();
                    break;
                case ACTIVATION_CONTEXT_SECTION_ID.COM_SERVER_REDIRECTION:
                    ComServers = ReadGuidSection<ACTIVATION_CONTEXT_DATA_COM_SERVER_REDIRECTION>(handle, toc_entry)
                            .Select(e => new ActivationContextDataComServerRedirection(e, handle, toc_entry.Offset, e.Offset)).ToReadOnlyList();
                    break;
                case ACTIVATION_CONTEXT_SECTION_ID.COM_INTERFACE_REDIRECTION:
                    ComInterfaces = ReadGuidSection<ACTIVATION_CONTEXT_DATA_COM_INTERFACE_REDIRECTION>(handle, toc_entry)
                        .Select(e => new ActivationContextDataComInterfaceRedirection(e, handle, toc_entry.Offset)).ToReadOnlyList();
                    break;
                case ACTIVATION_CONTEXT_SECTION_ID.COM_TYPE_LIBRARY_REDIRECTION:
                    ComTypeLibs = ReadGuidSection<ACTIVATION_CONTEXT_DATA_COM_TYPE_LIBRARY_REDIRECTION>(handle, toc_entry)
                        .Select(e => new ActivationContextDataComTypeLibraryRedirection(e, handle, toc_entry.Offset)).ToReadOnlyList();
                    break;
                case ACTIVATION_CONTEXT_SECTION_ID.CLASS_REDIRECTION:
                    WindowClasses = ReadStringSection<ACTIVATION_CONTEXT_DATA_WINDOW_CLASS_REDIRECTION>(handle, toc_entry)
                        .Select(e => new ActivationContextDataWindowClassRedirection(e, handle, toc_entry.Offset)).ToReadOnlyList();
                    break;
            }
        }
    }
}
