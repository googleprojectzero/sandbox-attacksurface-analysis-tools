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

using NtCoreLib.Native.SafeHandles;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.BindFilter.Interop;

internal static class NativeMethods
{
    [DllImport("bindfltapi.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus CreateBindLink(
        string virtualPath,
        string backingPath,
        CreateBindLinkFlags createBindLinkFlags,
        int exceptionCount,
        [MarshalAs(UnmanagedType.LPArray)] string[] exceptionPaths
    );

    [DllImport("bindfltapi.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus RemoveBindLink(
        string virtualPath
    );

    [DllImport("bindfltapi.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus BfSetupFilterEx(
     SafeKernelObjectHandle JobHandle,
     SafeSidBufferHandle Sid,
     BfSetupFilterFlags Flags,
     string VirtualizationRootPath,
     string VirtualizationTargetPath,
     [MarshalAs(UnmanagedType.LPArray)] string[] VirtualizationExceptionPaths,
     int VirtualizationExceptionPathCount
 );

    [DllImport("bindfltapi.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus BfRemoveMapping(
        SafeKernelObjectHandle JobHandle,
        string VirtualizationRootPath
    );

    [DllImport("bindfltapi.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus BfRemoveMappingEx(
        SafeKernelObjectHandle JobHandle,
        SafeSidBufferHandle Sid,
        string VirtualizationRootPath
    );

    [DllImport("bindfltapi.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus BfGetMappings(
        BfGetMappingFlags Flags,
        SafeKernelObjectHandle JobHandle,
        string VirtualizationRootPath,
        SafeSidBufferHandle Sid,
        ref int BufferSize,
        SafeBuffer OutBuffer
    );
}
