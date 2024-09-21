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

using System.Runtime.InteropServices;
using NtCoreLib.Win32.SideBySide.Parser;

namespace NtCoreLib.Win32.SideBySide.Interop;

[StructLayout(LayoutKind.Sequential, Pack = 4)]
struct ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION
{
    public int Size;                                 // size of this structure, in bytes
    public ActivationContextDataAssemblyInformationFlags Flags;
    public int EncodedAssemblyIdentityLength;        // in bytes
    public int EncodedAssemblyIdentityOffset;        // offset from section header base

    public ActivationContextPathType ManifestPathType;
    public int ManifestPathLength;                   // in bytes
    public int ManifestPathOffset;                   // offset from section header base
    public LargeIntegerStruct ManifestLastWriteTime;
    public ActivationContextPathType PolicyPathType;
    public int PolicyPathLength;                     // in bytes
    public int PolicyPathOffset;                     // offset from section header base
    public LargeIntegerStruct PolicyLastWriteTime;
    public int MetadataSatelliteRosterIndex;
    public int Unused2;
    public int ManifestVersionMajor;
    public int ManifestVersionMinor;
    public int PolicyVersionMajor;
    public int PolicyVersionMinor;
    public int AssemblyDirectoryNameLength; // in bytes
    public int AssemblyDirectoryNameOffset; // from section header base
    public int NumOfFilesInAssembly;
    public int LanguageLength; // in bytes
    public int LanguageOffset; // from section header base
    public ActivationContextRequestedRunLevel RunLevel;
    public int UiAccess;
}
