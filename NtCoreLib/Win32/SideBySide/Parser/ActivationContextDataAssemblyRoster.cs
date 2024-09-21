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
/// Class to represent an activation context assembly information.
/// </summary>
public sealed class ActivationContextDataAssemblyRoster
{
    /// <summary>
    /// Name of the assembly.
    /// </summary>
    public string AssemblyName { get; }

    /// <summary>
    /// Assembly directory name.
    /// </summary>
    public string AssemblyDirectoryName => AssemblyInformation?.AssemblyDirectoryName ?? string.Empty;

    /// <summary>
    /// Full path to the assembly directory.
    /// </summary>
    public string FullPath { get; }

    /// <summary>
    /// The assembly information is known.
    /// </summary>
    public ActivationContextDataAssemblyInformation AssemblyInformation { get; }

    /// <summary>
    /// Flags for the assembly.
    /// </summary>
    public ActivationContextDataAssemblyRosterFlags Flags { get; }

    private static readonly string SXS_FOLDER = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS");

    internal ActivationContextDataAssemblyRoster(ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY entry, SafeBufferGeneric handle, int base_offset)
    {
        AssemblyName = string.Empty;
        FullPath = string.Empty;
        Flags = entry.Flags;

        if (Flags.HasFlagSet(ActivationContextDataAssemblyRosterFlags.Invalid))
        {
            return;
        }

        AssemblyName = handle.ReadString(entry.AssemblyNameOffset, entry.AssemblyNameLength);
        if (entry.AssemblyInformationOffset == 0)
        {
            return;
        }

        var info = handle.ReadStruct<ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION>(entry.AssemblyInformationOffset);
        AssemblyInformation = new ActivationContextDataAssemblyInformation(info, handle, base_offset);
        FullPath = Path.Combine(SXS_FOLDER, AssemblyDirectoryName);
    }
}
