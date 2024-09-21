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
/// Class to represent detailed assembly information.
/// </summary>
public sealed class ActivationContextDataAssemblyInformation
{
    /// <summary>
    /// Assembly flags.
    /// </summary>
    public ActivationContextDataAssemblyInformationFlags Flags { get; }

    /// <summary>
    /// Assembly identity.
    /// </summary>
    public string EncodedAssemblyIdentity { get; }
    
    /// <summary>
    /// Manifest path type.
    /// </summary>
    public ActivationContextPathType ManifestPathType { get; }

    /// <summary>
    /// The manifest path.
    /// </summary>
    public string ManifestPath { get; }

    /// <summary>
    /// Manifest last write time.
    /// </summary>
    public DateTime ManifestLastWriteTime { get; }

    /// <summary>
    /// Policy path type.
    /// </summary>
    public ActivationContextPathType PolicyPathType { get; }

    /// <summary>
    /// Policy path.
    /// </summary>
    public string PolicyPath { get; }

    /// <summary>
    /// Policy last write time.
    /// </summary>
    public DateTime PolicyLastWriteTime { get; }

    /// <summary>
    /// Metadata satellite roster index.
    /// </summary>
    public int MetadataSatelliteRosterIndex { get; }

    /// <summary>
    /// Manifest version.
    /// </summary>
    public Version ManifestVersion { get; }

    /// <summary>
    /// Policy version.
    /// </summary>
    public Version PolicyVersion { get; }

    /// <summary>
    /// Assembly directory name.
    /// </summary>
    public string AssemblyDirectoryName { get; }

    /// <summary>
    /// Number of files in the assembly.
    /// </summary>
    public int NumOfFilesInAssembly { get; }

    /// <summary>
    /// Language.
    /// </summary>
    public string Language { get; }

    /// <summary>
    /// Runlevel.
    /// </summary>
    public ActivationContextRequestedRunLevel RunLevel;

    /// <summary>
    /// UI access.
    /// </summary>
    public bool UiAccess;

    internal ActivationContextDataAssemblyInformation(ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION info, SafeBufferGeneric handle, int base_offset)
    {
        EncodedAssemblyIdentity = handle.ReadString(base_offset + info.EncodedAssemblyIdentityOffset, info.EncodedAssemblyIdentityLength);
        ManifestPathType = info.ManifestPathType;
        ManifestPath = handle.ReadString(base_offset + info.ManifestPathOffset, info.ManifestPathLength);
        ManifestLastWriteTime = info.ManifestLastWriteTime.ToDateTime();
        PolicyPathType = info.PolicyPathType;
        PolicyPath = handle.ReadString(base_offset + info.PolicyPathOffset, info.PolicyPathLength);
        PolicyLastWriteTime = info.PolicyLastWriteTime.ToDateTime();
        MetadataSatelliteRosterIndex = info.MetadataSatelliteRosterIndex;
        ManifestVersion = new(info.ManifestVersionMajor, info.ManifestVersionMinor);
        PolicyVersion = new(info.PolicyVersionMajor, info.PolicyVersionMinor);
        AssemblyDirectoryName = handle.ReadString(base_offset + info.AssemblyDirectoryNameOffset, info.AssemblyDirectoryNameLength);
        NumOfFilesInAssembly = info.NumOfFilesInAssembly;
        Language = handle.ReadString(base_offset + info.LanguageOffset, info.LanguageLength);
        RunLevel = info.RunLevel;
        UiAccess = info.UiAccess != 0;
    }
}
