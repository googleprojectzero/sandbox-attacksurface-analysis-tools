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

[StructLayout(LayoutKind.Sequential)]
struct ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY
{
    public ActivationContextDataAssemblyRosterFlags Flags;
    public uint PseudoKey;                // case-insentively-hashed assembly name
    public int AssemblyNameOffset;       // from ACTIVATION_CONTEXT_DATA base
    public int AssemblyNameLength;       // length in bytes
    public int AssemblyInformationOffset; // from ACTIVATION_CONTEXT_DATA base to ACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION
    public int AssemblyInformationLength; // length in bytes
}
