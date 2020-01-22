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

using NtApiDotNet.Utilities.Memory;
using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [StructLayout(LayoutKind.Sequential), CrossBitnessType(typeof(RtlDriveLetterCurDir32))]
    public struct RtlDriveLetterCurDir
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public UnicodeStringOut DosPath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct RtlDriveLetterCurDir32 : IConvertToNative<RtlDriveLetterCurDir>
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public UnicodeStringOut32 DosPath;

        public RtlDriveLetterCurDir Convert()
        {
            return new RtlDriveLetterCurDir()
            {
                Flags = Flags,
                Length = Length,
                TimeStamp = TimeStamp,
                DosPath = DosPath.Convert()
            };
        }
    }

    [StructLayout(LayoutKind.Sequential), CrossBitnessType(typeof(CurDir32))]
    public struct CurDir
    {
        public UnicodeStringOut DosPath;
        public IntPtr Handle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct CurDir32 : IConvertToNative<CurDir>
    {
        public UnicodeStringOut32 DosPath;
        public IntPtr32 Handle;

        public CurDir Convert()
        {
            return new CurDir()
            {
                DosPath = DosPath.Convert(),
                Handle = Handle.Convert()
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RtlUserProcessParametersHeader
    {
        public int MaximumLength;
        public int Length;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RtlUserProcessParameters
    {
        public int MaximumLength;
        public int Length;
        public int Flags;
        public int DebugFlags;
        public IntPtr ConsoleHandle;
        public int ConsoleFlags;
        public IntPtr StdInputHandle;
        public IntPtr StdOutputHandle;
        public IntPtr StdErrorHandle;
        public CurDir CurrentDirectory;
        public UnicodeStringOut DllPath;
        public UnicodeStringOut ImagePathName;
        public UnicodeStringOut CommandLine;
        public IntPtr Environment;
        public int StartingPositionLeft;
        public int StartingPositionTop;
        public int Width;
        public int Height;
        public int CharWidth;
        public int CharHeight;
        public int ConsoleTextAttributes;
        public int WindowFlags;
        public int ShowWindowFlags;
        public UnicodeStringOut WindowTitle;
        public UnicodeStringOut DesktopName;
        public UnicodeStringOut ShellInfo;
        public UnicodeStringOut RuntimeData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
        public RtlDriveLetterCurDir[] CurrentDirectores;
        public IntPtr EnvironmentSize;
        public IntPtr EnvironmentVersion;
        public IntPtr PackageDependencyData;
        public int ProcessGroupId;
        public int LoaderThreads;
        public UnicodeStringOut RedirectionDllName;
        public UnicodeStringOut HeapPartitionName;
        public IntPtr DefaultThreadpoolCpuSetMasks;
        public int DefaultThreadpoolCpuSetMaskCount;

        internal NtUserProcessParameters ToObject(NtProcess process)
        {
            return new NtUserProcessParameters()
            {
                Flags = Flags,
                DebugFlags = DebugFlags,
                ConsoleHandle = ConsoleHandle,
                ConsoleFlags = ConsoleFlags,
                StdInputHandle = StdInputHandle,
                StdOutputHandle = StdOutputHandle,
                StdErrorHandle = StdErrorHandle,
                CurrentDirectoryPath = CurrentDirectory.DosPath.ToString(process),
                CurrentDirectoryHandle = CurrentDirectory.Handle,
                DllPath = DllPath.ToString(process),
                ImagePathName = ImagePathName.ToString(process),
                CommandLine = CommandLine.ToString(process),
                Environment = Environment,
                StartingPositionLeft = StartingPositionLeft,
                StartingPositionTop = StartingPositionTop,
                Width = Width,
                Height = Height,
                CharWidth = CharWidth,
                CharHeight = CharHeight,
                ConsoleTextAttributes = ConsoleTextAttributes,
                WindowFlags = WindowFlags,
                ShowWindowFlags = ShowWindowFlags,
                WindowTitle = WindowTitle.ToString(process),
                DesktopName = DesktopName.ToString(process),
                ShellInfo = ShellInfo.ToString(process),
                RuntimeData = RuntimeData.ToString(process),
                //CurrentDirectores = CurrentDirectores.Select(d => d.Convert()).ToArray(),
                EnvironmentSize = EnvironmentSize,
                EnvironmentVersion = EnvironmentVersion,
                PackageDependencyData = PackageDependencyData,
                ProcessGroupId = ProcessGroupId,
                LoaderThreads = LoaderThreads,
                RedirectionDllName = RedirectionDllName.ToString(process),
                HeapPartitionName = HeapPartitionName.ToString(process),
                DefaultThreadpoolCpuSetMasks = DefaultThreadpoolCpuSetMasks,
                DefaultThreadpoolCpuSetMaskCount = DefaultThreadpoolCpuSetMaskCount
            };
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct RtlUserProcessParameters32 : IConvertToNative<RtlUserProcessParameters>
    {
        public int MaximumLength;
        public int Length;
        public int Flags;
        public int DebugFlags;
        public IntPtr32 ConsoleHandle;
        public int ConsoleFlags;
        public IntPtr32 StdInputHandle;
        public IntPtr32 StdOutputHandle;
        public IntPtr32 StdErrorHandle;
        public CurDir32 CurrentDirectory;
        public UnicodeStringOut32 DllPath;
        public UnicodeStringOut32 ImagePathName;
        public UnicodeStringOut32 CommandLine;
        public IntPtr32 Environment;
        public int StartingPositionLeft;
        public int StartingPositionTop;
        public int Width;
        public int Height;
        public int CharWidth;
        public int CharHeight;
        public int ConsoleTextAttributes;
        public int WindowFlags;
        public int ShowWindowFlags;
        public UnicodeStringOut32 WindowTitle;
        public UnicodeStringOut32 DesktopName;
        public UnicodeStringOut32 ShellInfo;
        public UnicodeStringOut32 RuntimeData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
        public RtlDriveLetterCurDir32[] CurrentDirectores;
        public IntPtr32 EnvironmentSize;
        public IntPtr32 EnvironmentVersion;
        public IntPtr32 PackageDependencyData;
        public int ProcessGroupId;
        public int LoaderThreads;
        public UnicodeStringOut32 RedirectionDllName;
        public UnicodeStringOut32 HeapPartitionName;
        public IntPtr32 DefaultThreadpoolCpuSetMasks;
        public int DefaultThreadpoolCpuSetMaskCount;

        public RtlUserProcessParameters Convert()
        {
            return new RtlUserProcessParameters()
            {
                MaximumLength = MaximumLength,
                Length = Length,
                Flags = Flags,
                DebugFlags = DebugFlags,
                ConsoleHandle = ConsoleHandle.Convert(),
                ConsoleFlags = ConsoleFlags,
                StdInputHandle = StdInputHandle.Convert(),
                StdOutputHandle = StdOutputHandle.Convert(),
                StdErrorHandle = StdErrorHandle.Convert(),
                CurrentDirectory = CurrentDirectory.Convert(),
                DllPath = DllPath.Convert(),
                ImagePathName = ImagePathName.Convert(),
                CommandLine = CommandLine.Convert(),
                Environment = Environment.Convert(),
                StartingPositionLeft = StartingPositionLeft,
                StartingPositionTop = StartingPositionTop,
                Width = Width,
                Height = Height,
                CharWidth = CharWidth,
                CharHeight = CharHeight,
                ConsoleTextAttributes = ConsoleTextAttributes,
                WindowFlags = WindowFlags,
                ShowWindowFlags = ShowWindowFlags,
                WindowTitle = WindowTitle.Convert(),
                DesktopName = DesktopName.Convert(),
                ShellInfo = ShellInfo.Convert(),
                RuntimeData = RuntimeData.Convert(),
                CurrentDirectores = CurrentDirectores.Select(d => d.Convert()).ToArray(),
                EnvironmentSize = EnvironmentSize.Convert(),
                EnvironmentVersion = EnvironmentVersion.Convert(),
                PackageDependencyData = PackageDependencyData.Convert(),
                ProcessGroupId = ProcessGroupId,
                LoaderThreads = LoaderThreads,
                RedirectionDllName = RedirectionDllName.Convert(),
                HeapPartitionName = HeapPartitionName.Convert(),
                DefaultThreadpoolCpuSetMasks = DefaultThreadpoolCpuSetMasks.Convert(),
                DefaultThreadpoolCpuSetMaskCount = DefaultThreadpoolCpuSetMaskCount
            };
        }
    }

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
        public RtlDriveLetterCurDir[] CurrentDirectores { get; }
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
}
