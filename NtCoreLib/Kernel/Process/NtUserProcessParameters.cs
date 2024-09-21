//  Copyright 2020 Google Inc. All Rights Reserved.
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

using System;

namespace NtCoreLib.Kernel.Process;

#pragma warning disable 1591

/// <summary>
/// Converted user process parameters.
/// </summary>
public sealed class NtUserProcessParameters
{
    public int Flags { get; set; }
    public int DebugFlags { get; set; }
    public IntPtr ConsoleHandle { get; set; }
    public int ConsoleFlags { get; set; }
    public IntPtr StdInputHandle { get; set; }
    public IntPtr StdOutputHandle { get; set; }
    public IntPtr StdErrorHandle { get; set; }
    public string CurrentDirectoryPath { get; set; }
    public IntPtr CurrentDirectoryHandle { get; set; }
    public string DllPath { get; set; }
    public string ImagePathName { get; set; }
    public string CommandLine { get; set; }
    public IntPtr Environment { get; set; }
    public int StartingPositionLeft { get; set; }
    public int StartingPositionTop { get; set; }
    public int Width { get; set; }
    public int Height { get; set; }
    public int CharWidth { get; set; }
    public int CharHeight { get; set; }
    public int ConsoleTextAttributes { get; set; }
    public int WindowFlags { get; set; }
    public int ShowWindowFlags { get; set; }
    public string WindowTitle { get; set; }
    public string DesktopName { get; set; }
    public string ShellInfo { get; set; }
    public string RuntimeData { get; set; }
    public RtlDriveLetterCurDir[] CurrentDirectories { get; set; }
    public IntPtr EnvironmentSize { get; set; }
    public IntPtr EnvironmentVersion { get; set; }
    public IntPtr PackageDependencyData { get; set; }
    public int ProcessGroupId { get; set; }
    public int LoaderThreads { get; set; }
    public string RedirectionDllName { get; set; }
    public string HeapPartitionName { get; set; }
    public IntPtr DefaultThreadpoolCpuSetMasks { get; set; }
    public int DefaultThreadpoolCpuSetMaskCount { get; set; }
}
#pragma warning restore 1591

