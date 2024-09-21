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

using NtCoreLib.Image;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.SideBySide;

/// <summary>
/// Configuration for creating an activation context.
/// </summary>
public struct ActivationContextConfig
{
    /// <summary>
    /// The source path for the manifest.
    /// </summary>
    public string Source;

    /// <summary>
    /// The processor architecture.
    /// </summary>
    public DllMachineType? ProcessorArchitecture;

    /// <summary>
    /// The language ID.
    /// </summary>
    public ushort? LangId;

    /// <summary>
    /// The assembly directory for private assemblies.
    /// </summary>
    public string AssemblyDirectory;

    /// <summary>
    /// The name of the resource in the file path if an executable.
    /// </summary>
    public ResourceString ResourceName;

    /// <summary>
    /// The name of the application.
    /// </summary>
    public string ApplicationName;

    /// <summary>
    /// The module containing the resource.
    /// </summary>
    public SafeHandle Module;

    /// <summary>
    /// True to set the context for process default.
    /// </summary>
    public bool SetProcessDefault;

    /// <summary>
    /// True to indicate the source is an assembly reference.
    /// </summary>
    public bool SourceIsAssemblyRef;
}
