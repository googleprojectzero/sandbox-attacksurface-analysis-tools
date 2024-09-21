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
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NtCoreLib.Win32.Filter.Interop;

internal static class NativeMethods
{
    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterFindFirst(
      FILTER_INFORMATION_CLASS dwInformationClass,
      SafeBuffer lpBuffer,
      int dwBufferSize,
      out int lpBytesReturned,
      out IntPtr lpFilterFind
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterFindNext(
      IntPtr hFilterFind,
      FILTER_INFORMATION_CLASS dwInformationClass,
      SafeBuffer lpBuffer,
      int dwBufferSize,
      out int lpBytesReturned
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterFindClose(
        IntPtr hFilterFind
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterInstanceFindFirst(
        string lpFilterName,
        INSTANCE_INFORMATION_CLASS dwInformationClass,
        SafeBuffer lpBuffer,
        int dwBufferSize,
        out int lpBytesReturned,
        out IntPtr lpFilterInstanceFind
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterInstanceFindNext(
        IntPtr hFilterInstanceFind,
        INSTANCE_INFORMATION_CLASS dwInformationClass,
        SafeBuffer lpBuffer,
        int dwBufferSize,
        out int lpBytesReturned
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterInstanceFindClose(
        IntPtr hFilterInstanceFind
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterAttach(
        string lpFilterName,
        string lpVolumeName,
        string lpInstanceName,
        int dwCreatedInstanceNameLength,
        StringBuilder lpCreatedInstanceName
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterDetach(
        string lpFilterName,
        string lpVolumeName,
        string lpInstanceName
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterAttachAtAltitude(
        string lpFilterName,
        string lpVolumeName,
        string lpAltitude,
        string lpInstanceName,
        int dwCreatedInstanceNameLength,
        StringBuilder lpCreatedInstanceName
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterVolumeFindFirst(
        FILTER_VOLUME_INFORMATION_CLASS dwInformationClass,
        SafeBuffer lpBuffer,
        int dwBufferSize,
        out int lpBytesReturned,
        out IntPtr lpVolumeFind
        );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterVolumeFindNext(
        IntPtr hVolumeFind,
        FILTER_VOLUME_INFORMATION_CLASS dwInformationClass,
        SafeBuffer lpBuffer,
        int dwBufferSize,
        out int lpBytesReturned
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterVolumeFindClose(
        IntPtr hVolumeFind
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterVolumeInstanceFindFirst(
        string lpVolumeName,
        INSTANCE_INFORMATION_CLASS dwInformationClass,
        SafeBuffer lpBuffer,
        int dwBufferSize,
        out int lpBytesReturned,
        out IntPtr lpVolumeInstanceFind
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterVolumeInstanceFindNext(
        IntPtr hVolumeInstanceFind,
        INSTANCE_INFORMATION_CLASS dwInformationClass,
        SafeBuffer lpBuffer,
        int dwBufferSize,
        out int lpBytesReturned
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterVolumeInstanceFindClose(
        IntPtr hVolumeInstanceFind
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterConnectCommunicationPort(
      string lpPortName,
      FilterConnectFlags dwOptions,
      byte[] lpContext,
      short wSizeOfContext,
      SECURITY_ATTRIBUTES lpSecurityAttributes,
      out SafeKernelObjectHandle hPort
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterSendMessage(
      SafeKernelObjectHandle hPort,
      SafeBuffer lpInBuffer,
      int dwInBufferSize,
      SafeBuffer lpOutBuffer,
      int dwOutBufferSize,
      out int lpBytesReturned
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterReplyMessage(
      SafeKernelObjectHandle hPort,
      SafeBuffer lpReplyBuffer, // PFILTER_REPLY_HEADER
      int dwReplyBufferSize
    );

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    internal static extern NtStatus FilterGetMessage(
        SafeKernelObjectHandle hPort,
        SafeBuffer lpMessageBuffer, // PFILTER_MESSAGE_HEADER 
        int dwMessageBufferSize,
        IntPtr lpOverlapped
    );
}
