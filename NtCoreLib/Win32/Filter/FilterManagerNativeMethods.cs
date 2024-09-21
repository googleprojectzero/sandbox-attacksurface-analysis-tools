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
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32.Filter
{
    internal enum FILTER_INFORMATION_CLASS
    {
        FilterFullInformation,
        FilterAggregateBasicInformation,
        FilterAggregateStandardInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILTER_AGGREGATE_STANDARD_INFORMATION_MINI_FILTER
    {
        public int Flags;
        public int FrameID;
        public int NumberOfInstances;
        public ushort FilterNameLength;
        public ushort FilterNameBufferOffset;
        public ushort FilterAltitudeLength;
        public ushort FilterAltitudeBufferOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILTER_AGGREGATE_STANDARD_INFORMATION_LEGACY_FILTER
    {
        public int Flags;
        public ushort FilterNameLength;
        public ushort FilterNameBufferOffset;
        public ushort FilterAltitudeLength;
        public ushort FilterAltitudeBufferOffset;
    }

    internal enum FILTER_AGGREGATE_STANDARD_INFORMATION_FLAGS
    {
        FLTFL_ASI_IS_MINIFILTER = 0x00000001,
        FLTFL_ASI_IS_LEGACYFILTER = 0x00000002
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct FILTER_AGGREGATE_STANDARD_INFORMATION
    {
        [FieldOffset(0)]
        public int NextEntryOffset;
        [FieldOffset(4)]
        public FILTER_AGGREGATE_STANDARD_INFORMATION_FLAGS Flags;
        [FieldOffset(8)]
        public FILTER_AGGREGATE_STANDARD_INFORMATION_MINI_FILTER MiniFilter;
        [FieldOffset(8)]
        public FILTER_AGGREGATE_STANDARD_INFORMATION_LEGACY_FILTER LegacyFilter;
    }

    internal enum INSTANCE_INFORMATION_CLASS
    {

        InstanceBasicInformation,
        InstancePartialInformation,
        InstanceFullInformation,
        InstanceAggregateStandardInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILTER_INSTANCE_FULL_INFORMATION
    {
        public int NextEntryOffset;
        public ushort InstanceNameLength;
        public ushort InstanceNameBufferOffset;
        public ushort AltitudeLength;
        public ushort AltitudeBufferOffset;
        public ushort VolumeNameLength;
        public ushort VolumeNameBufferOffset;
        public ushort FilterNameLength;
        public ushort FilterNameBufferOffset;
    }

    internal enum FILTER_VOLUME_INFORMATION_CLASS
    {
        FilterVolumeBasicInformation,
        FilterVolumeStandardInformation
    }

    [Flags]
    internal enum FILTER_VOLUME_STANDARD_INFORMATION_FLAGS
    {
        None = 0,
        FLTFL_VSI_DETACHED_VOLUME = 0x00000001
    }

    /// <summary>
    /// Filter filesystem type.
    /// </summary>
    public enum FilterFilesystemType
    {
        /// <summary>
        /// an UNKNOWN file system type
        /// </summary>
        UNKNOWN,
        /// <summary>
        /// Microsoft's RAW file system       (\FileSystem\RAW)
        /// </summary>
        RAW,
        /// <summary>
        /// Microsoft's NTFS file system      (\FileSystem\Ntfs)
        /// </summary>
        NTFS,
        /// <summary>
        /// Microsoft's FAT file system       (\FileSystem\Fastfat)
        /// </summary>
        FAT,
        /// <summary>
        /// Microsoft's CDFS file system      (\FileSystem\Cdfs)
        /// </summary>
        CDFS,
        /// <summary>
        /// Microsoft's UDFS file system      (\FileSystem\Udfs)
        /// </summary>
        UDFS,
        /// <summary>
        /// Microsoft's LanMan Redirector     (\FileSystem\MRxSmb)
        /// </summary>
        LANMAN,
        /// <summary>
        /// Microsoft's WebDav redirector     (\FileSystem\MRxDav)
        /// </summary>
        WEBDAV,
        /// <summary>
        /// Microsoft's Terminal Server redirector    (\Driver\rdpdr)
        /// </summary>
        RDPDR,
        /// <summary>
        /// Microsoft's NFS file system       (\FileSystem\NfsRdr)
        /// </summary>
        NFS,
        /// <summary>
        /// Microsoft's NetWare redirector    (\FileSystem\nwrdr)
        /// </summary>
        MS_NETWARE,
        /// <summary>
        /// Novell's NetWare redirector
        /// </summary>
        NETWARE,
        /// <summary>
        /// The BsUDF CD-ROM driver           (\FileSystem\BsUDF)
        /// </summary>
        BSUDF,
        /// <summary>
        /// Microsoft's Mup redirector        (\FileSystem\Mup)
        /// </summary>
        MUP,
        /// <summary>
        /// Microsoft's WinFS redirector      (\FileSystem\RsFxDrv)
        /// </summary>
        RSFX,
        /// <summary>
        /// Roxio's UDF writeable file system (\FileSystem\cdudf_xp)
        /// </summary>
        ROXIO_UDF1,
        /// <summary>
        /// Roxio's UDF readable file system  (\FileSystem\UdfReadr_xp)
        /// </summary>
        ROXIO_UDF2,
        /// <summary>
        /// Roxio's DVD file system           (\FileSystem\DVDVRRdr_xp)
        /// </summary>
        ROXIO_UDF3,
        /// <summary>
        /// Tacit FileSystem                  (\Device\TCFSPSE)
        /// </summary>
        TACIT,
        /// <summary>
        /// Microsoft's File system recognizer (\FileSystem\Fs_rec)
        /// </summary>
        FS_REC,
        /// <summary>
        /// Nero's InCD file system           (\FileSystem\InCDfs)
        /// </summary>
        INCD,
        /// <summary>
        /// Nero's InCD FAT file system       (\FileSystem\InCDFat)
        /// </summary>
        INCD_FAT,
        /// <summary>
        /// Microsoft's EXFat FILE SYSTEM     (\FileSystem\exfat)
        /// </summary>
        EXFAT,
        /// <summary>
        /// PolyServ's file system            (\FileSystem\psfs)
        /// </summary>
        PSFS,
        /// <summary>
        /// IBM General Parallel File System  (\FileSystem\gpfs)
        /// </summary>
        GPFS,
        /// <summary>
        /// Microsoft's Named Pipe file system(\FileSystem\npfs)
        /// </summary>
        NPFS,
        /// <summary>
        /// Microsoft's Mailslot file system  (\FileSystem\msfs)
        /// </summary>
        MSFS,
        /// <summary>
        /// Microsoft's Cluster Shared Volume file system  (\FileSystem\csvfs)
        /// </summary>
        CSVFS,
        /// <summary>
        /// Microsoft's ReFS file system      (\FileSystem\Refs or \FileSystem\Refsv1)
        /// </summary>
        REFS,
        /// <summary>
        /// OpenAFS file system               (\Device\AFSRedirector)
        /// </summary>
        OPENAFS,
        /// <summary>
        /// Composite Image file system       (\FileSystem\cimfs)
        /// </summary>
        CIMFS
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("FilterVolumeName")]
    internal struct FILTER_VOLUME_STANDARD_INFORMATION
    {
        public int NextEntryOffset;
        public FILTER_VOLUME_STANDARD_INFORMATION_FLAGS Flags;
        public int FrameID;
        public FilterFilesystemType FileSystemType;
        public ushort FilterVolumeNameLength;
        public char FilterVolumeName;
    }

    [Flags]
    internal enum FilterConnectFlags
    {
        NONE = 0,
        FLT_PORT_FLAG_SYNC_HANDLE = 0x00000001
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILTER_MESSAGE_HEADER
    {
        public int ReplyLength;
        public ulong MessageId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILTER_REPLY_HEADER
    {
        public NtStatus Status;
        public ulong MessageId;
    }

    internal static class FilterManagerNativeMethods
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
}
