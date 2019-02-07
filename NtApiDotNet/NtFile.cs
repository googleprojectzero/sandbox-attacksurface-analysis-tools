//  Copyright 2016 Google Inc. All Rights Reserved.
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

using Microsoft.Win32.SafeHandles;
using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NtApiDotNet
{
#pragma warning disable 1591
    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenFile(
            out SafeKernelObjectHandle FileHandle,
            FileAccessRights DesiredAccess,
            ObjectAttributes ObjAttr,
            [Out] IoStatus IoStatusBlock,
            FileShareMode ShareAccess,
            FileOpenOptions OpenOptions);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateFile(
            out SafeKernelObjectHandle FileHandle,
            FileAccessRights DesiredAccess,
            ObjectAttributes ObjAttr,
            [Out] IoStatus IoStatusBlock,
            LargeInteger AllocationSize,
            FileAttributes FileAttributes,
            FileShareMode ShareAccess,
            FileDisposition CreateDisposition,
            FileOpenOptions CreateOptions,
            byte[] EaBuffer,
            int EaLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDeviceIoControlFile(
          SafeKernelObjectHandle FileHandle,
          SafeKernelObjectHandle Event,
          IntPtr ApcRoutine,
          IntPtr ApcContext,
          SafeIoStatusBuffer IoStatusBlock,
          int IoControlCode,
          IntPtr InputBuffer,
          int InputBufferLength,
          IntPtr OutputBuffer,
          int OutputBufferLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtFsControlFile(
          SafeKernelObjectHandle FileHandle,
          SafeKernelObjectHandle Event,
          IntPtr ApcRoutine,
          IntPtr ApcContext,
          SafeIoStatusBuffer IoStatusBlock,
          int FSControlCode,
          IntPtr InputBuffer,
          int InputBufferLength,
          IntPtr OutputBuffer,
          int OutputBufferLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationFile(
          SafeKernelObjectHandle FileHandle,
          [Out] IoStatus IoStatusBlock,
          SafeBuffer FileInformation,
          int Length,
          FileInformationClass FileInformationClass
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationFile(
            SafeKernelObjectHandle FileHandle,
            [Out] IoStatus IoStatusBlock,
            SafeBuffer FileInformation,
            int Length,
            FileInformationClass FileInformationClass);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryVolumeInformationFile(
          SafeKernelObjectHandle FileHandle,
          [Out] IoStatus IoStatusBlock,
          SafeBuffer FsInformation,
          int Length,
          FsInformationClass FsInformationClass);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryDirectoryFile(
          SafeKernelObjectHandle FileHandle,
          SafeKernelObjectHandle Event,
          IntPtr ApcRoutine,
          IntPtr ApcContext,
          SafeIoStatusBuffer IoStatusBlock,
          SafeBuffer FileInformation,
          int Length,
          FileInformationClass FileInformationClass,
          [MarshalAs(UnmanagedType.U1)] bool ReturnSingleEntry,
          UnicodeString FileName,
          [MarshalAs(UnmanagedType.U1)] bool RestartScan
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtReadFile(
          SafeKernelObjectHandle FileHandle,
          SafeKernelObjectHandle Event,
          IntPtr ApcRoutine,
          IntPtr ApcContext,
          SafeIoStatusBuffer IoStatusBlock,
          SafeBuffer Buffer,
          int Length,
          [In] LargeInteger ByteOffset,
          IntPtr Key
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtWriteFile(
          SafeKernelObjectHandle FileHandle,
          SafeKernelObjectHandle Event,
          IntPtr ApcRoutine,
          IntPtr ApcContext,
          SafeIoStatusBuffer IoStatusBlock,
          SafeBuffer Buffer,
          int Length,
          [In] LargeInteger ByteOffset,
          IntPtr Key
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtLockFile(
          SafeKernelObjectHandle FileHandle,
          SafeKernelObjectHandle Event,
          IntPtr ApcRoutine,
          IntPtr ApcContext,
          SafeIoStatusBuffer IoStatusBlock,
          [In] LargeInteger ByteOffset,
          [In] LargeInteger Length,
          int Key,
          bool FailImmediately,
          bool ExclusiveLock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtUnlockFile(
          SafeKernelObjectHandle FileHandle,
          IoStatus IoStatusBlock,
          [In] LargeInteger ByteOffset,
          [In] LargeInteger Length,
          int Key);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateNamedPipeFile(
            out SafeKernelObjectHandle FileHandle,
            FileAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            [Out] IoStatus IoStatusBlock,
            FileShareMode ShareAccess,
            FileDisposition CreateDisposition,
            FileOpenOptions CreateOptions,
            NamedPipeType NamedPipeType,
            NamedPipeReadMode ReadMode,
            NamedPipeCompletionMode CompletionMode,
            int MaximumInstances,
            int InboundQuota,
            int OutboundQuota,
            LargeInteger DefaultTimeout
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateMailslotFile(
            out SafeKernelObjectHandle FileHandle,
            FileAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            [Out] IoStatus IoStatusBlock,
            FileOpenOptions CreateOptions,
            int MailslotQuota,
            int MaximumMessageSize,
            LargeInteger ReadTimeout
            );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCancelIoFileEx(
            SafeKernelObjectHandle FileHandle,
            SafeIoStatusBuffer IoRequestToCancel,
            [Out] IoStatus IoStatusBlock
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryEaFile(
          SafeKernelObjectHandle FileHandle,
          [Out] IoStatus IoStatusBlock,
          [Out] byte[] Buffer,
          int Length,
          bool ReturnSingleEntry,
          SafeBuffer EaList,
          int EaListLength,
          [In] OptionalInt32 EaIndex,
          bool RestartScan
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetEaFile(
          SafeKernelObjectHandle FileHandle,
          [Out] IoStatus IoStatusBlock,
          byte[] Buffer,
          int Length
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDeleteFile(
          [In] ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtReplacePartitionUnit(UnicodeString TargetInstancePath, 
            UnicodeString SpareInstancePath, uint Flags);
    }

    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlWow64EnableFsRedirection(bool Wow64FsEnableRedirection);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlWow64EnableFsRedirectionEx(IntPtr DisableFsRedirection, 
            out IntPtr OldFsRedirectionLevel);
    }

    [Flags]
    public enum NamedPipeType
    {
        Bytestream = 0x00000000,
        Message = 0x00000001,
        RejectRemoteClients = 0x00000002,
    }

    public enum NamedPipeCompletionMode
    {
        QueueOperation = 0,
        CompleteOperation = 1,
    }

    public enum NamedPipeReadMode
    {
        ByteStream = 0,
        Message = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    public class RtlRelativeName
    {
        public UnicodeStringOut RelativeName;
        public IntPtr ContainingDirectory;
        public IntPtr CurDirRef;
    }

    public enum RtlPathType
    {
        Unknown,
        UncAbsolute,
        DriveAbsolute,
        DriveRelative,
        Rooted,
        Relative,
        LocalDevice,
        RootLocalDevice
    }

    public static partial class NtRtl
    {

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus RtlDosPathNameToRelativeNtPathName_U_WithStatus(
          string DosFileName,
          out UnicodeStringOut NtFileName,
          out IntPtr ShortPath,
          [Out] RtlRelativeName RelativeName
          );

        [DllImport("ntdll.dll")]
        [return: MarshalAs(UnmanagedType.U1)]
        public static extern bool RtlReleaseRelativeName([In, Out] RtlRelativeName RelativeName);


        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern RtlPathType RtlDetermineDosPathNameType_U(string Path);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlDefaultNpAcl(out IntPtr NamedPipeAcl);
    }

    public enum FileDisposition
    {
        Supersede = 0x00000000,
        Open = 0x00000001,
        Create = 0x00000002,
        OpenIf = 0x00000003,
        Overwrite = 0x00000004,
        OverwriteIf = 0x00000005,
    }

    public enum FileOpenResult
    {
        Superseded = 0x00000000,
        Opened = 0x00000001,
        Created = 0x00000002,
        Overwritten = 0x00000003,
        Exists = 0x00000004,
        DoesNotExist = 0x00000005
    }

    [Flags]
    public enum FileAttributes : uint
    {
        None = 0,
        ReadOnly = 0x00000001,
        Hidden = 0x00000002,
        System = 0x00000004,
        Directory = 0x00000010,
        Archive = 0x00000020,
        Device = 0x00000040,
        Normal = 0x00000080,
        Temporary = 0x00000100,
        SparseFile = 0x00000200,
        ReparsePoint = 0x00000400,
        Compressed = 0x00000800,
        Offline = 0x00001000,
        NotContentIndexed = 0x00002000,
        Encrypted = 0x00004000,
        IntegrityStream = 0x00008000,
        Virtual = 0x00010000,
        NoScrubData = 0x00020000,
        Ea = 0x00040000,
        Pinned = 0x00080000,
        Unpinned = 0x00100000,
        RecallOnDataAccess = 0x00400000,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileTime
    {
        public uint DateTimeLow;
        public uint DateTimeHigh;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FileDispositionInformation
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool DeleteFile;
    }

    [Flags]
    public enum FileDispositionInformationExFlags : uint
    {
        None = 0,
        Delete = 0x00000001,
        PosixSemantics = 0x00000002,
        ForceImageSectionCheck = 0x00000004,
        OnClose = 0x00000008,
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FileDispositionInformationEx
    {
        public FileDispositionInformationExFlags Flags;
    }

    [Flags]
    public enum FileRenameInformationExFlags : uint
    {
        None = 0,
        ReplaceIfExists = 0x00000001,
        PosixSemantics = 0x00000002,
        SuppressPinStateInheritance = 0x00000004,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    [DataStart("FileName")]
    public class FileRenameInformationEx
    {
        public FileRenameInformationExFlags Flags;
        public IntPtr RootDirectory;
        public int FileNameLength;
        public char FileName; // Unused, place holder for start of data.
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    [DataStart("FileName")]
    public class FileLinkRenameInformation
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool ReplaceIfExists;
        public IntPtr RootDirectory;
        public int FileNameLength;
        public char FileName; // Unused, place holder for start of data.
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct FileInternalInformation
    {
        public LargeInteger IndexNumber;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileStandardInformation
    {
        public LargeIntegerStruct AllocationSize;
        public LargeIntegerStruct EndOfFile;
        public int NumberOfLinks;
        [MarshalAs(UnmanagedType.U1)] public bool DeletePending;
        [MarshalAs(UnmanagedType.U1)] public bool Directory;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("FileName")]
    public struct FileDirectoryInformation
    {
        public int NextEntryOffset;
        public int FileIndex;
        public LargeIntegerStruct CreationTime;
        public LargeIntegerStruct LastAccessTime;
        public LargeIntegerStruct LastWriteTime;
        public LargeIntegerStruct ChangeTime;
        public LargeIntegerStruct EndOfFile;
        public LargeIntegerStruct AllocationSize;
        public FileAttributes FileAttributes;
        public int FileNameLength;
        public ushort FileName; // String
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FilePositionInformation
    {
        public LargeIntegerStruct CurrentByteOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileEaInformation
    {
        public int EaSize;
    }

    public struct FileCompletionInformation
    {
        public IntPtr CompletionPort;
        public IntPtr Key;
    }

    public enum FileInformationClass
    {
        FileDirectoryInformation = 1,
        FileFullDirectoryInformation,
        FileBothDirectoryInformation,
        FileBasicInformation,
        FileStandardInformation,
        FileInternalInformation,
        FileEaInformation,
        FileAccessInformation,
        FileNameInformation,
        FileRenameInformation,
        FileLinkInformation,
        FileNamesInformation,
        FileDispositionInformation,
        FilePositionInformation,
        FileFullEaInformation,
        FileModeInformation,
        FileAlignmentInformation,
        FileAllInformation,
        FileAllocationInformation,
        FileEndOfFileInformation,
        FileAlternateNameInformation,
        FileStreamInformation,
        FilePipeInformation,
        FilePipeLocalInformation,
        FilePipeRemoteInformation,
        FileMailslotQueryInformation,
        FileMailslotSetInformation,
        FileCompressionInformation,
        FileObjectIdInformation,
        FileCompletionInformation,
        FileMoveClusterInformation,
        FileQuotaInformation,
        FileReparsePointInformation,
        FileNetworkOpenInformation,
        FileAttributeTagInformation,
        FileTrackingInformation,
        FileIdBothDirectoryInformation,
        FileIdFullDirectoryInformation,
        FileValidDataLengthInformation,
        FileShortNameInformation,
        FileIoCompletionNotificationInformation,
        FileIoStatusBlockRangeInformation,
        FileIoPriorityHintInformation,
        FileSfioReserveInformation,
        FileSfioVolumeInformation,
        FileHardLinkInformation,
        FileProcessIdsUsingFileInformation,
        FileNormalizedNameInformation,
        FileNetworkPhysicalNameInformation,
        FileIdGlobalTxDirectoryInformation,
        FileIsRemoteDeviceInformation,
        FileUnusedInformation,
        FileNumaNodeInformation,
        FileStandardLinkInformation,
        FileRemoteProtocolInformation,
        FileRenameInformationBypassAccessCheck,
        FileLinkInformationBypassAccessCheck,
        FileVolumeNameInformation,
        FileIdInformation,
        FileIdExtdDirectoryInformation,
        FileReplaceCompletionInformation,
        FileHardLinkFullIdInformation,
        FileIdExtdBothDirectoryInformation,
        FileDispositionInformationEx,
        FileRenameInformationEx,
        FileRenameInformationExBypassAccessCheck,
        FileDesiredStorageClassInformation,
        FileStatInformation,
        FileMemoryPartitionInformation,
        FileStatLxInformation,
        FileCaseSensitiveInformation,
        FileLinkInformationEx,
        FileLinkInformationExBypassAccessCheck,
        FileStorageReserveIdInformation,
        FileCaseSensitiveInformationForceAccessCheck,
        FileMaximumInformation
    }

    public enum FsInformationClass
    {
        FileFsVolumeInformation = 1,
        FileFsLabelInformation = 2,
        FileFsSizeInformation = 3,
        FileFsDeviceInformation = 4,
        FileFsAttributeInformation = 5,
        FileFsControlInformation = 6,
        FileFsFullSizeInformation = 7,
        FileFsObjectIdInformation = 8,
        FileFsDriverPathInformation = 9,
        FileFsVolumeFlagsInformation = 10,
        FileFsSectorSizeInformation = 11
    }

    public enum FileDeviceType
    {
        BEEP = 0x00000001,
        CD_ROM = 0x00000002,
        CD_ROM_FILE_SYSTEM = 0x00000003,
        CONTROLLER = 0x00000004,
        DATALINK = 0x00000005,
        DFS = 0x00000006,
        DISK = 0x00000007,
        DISK_FILE_SYSTEM = 0x00000008,
        FILE_SYSTEM = 0x00000009,
        INPORT_PORT = 0x0000000a,
        KEYBOARD = 0x0000000b,
        MAILSLOT = 0x0000000c,
        MIDI_IN = 0x0000000d,
        MIDI_OUT = 0x0000000e,
        MOUSE = 0x0000000f,
        MULTI_UNC_PROVIDER = 0x00000010,
        NAMED_PIPE = 0x00000011,
        NETWORK = 0x00000012,
        NETWORK_BROWSER = 0x00000013,
        NETWORK_FILE_SYSTEM = 0x00000014,
        NULL = 0x00000015,
        PARALLEL_PORT = 0x00000016,
        PHYSICAL_NETCARD = 0x00000017,
        PRINTER = 0x00000018,
        SCANNER = 0x00000019,
        SERIAL_MOUSE_PORT = 0x0000001a,
        SERIAL_PORT = 0x0000001b,
        SCREEN = 0x0000001c,
        SOUND = 0x0000001d,
        STREAMS = 0x0000001e,
        TAPE = 0x0000001f,
        TAPE_FILE_SYSTEM = 0x00000020,
        TRANSPORT = 0x00000021,
        UNKNOWN = 0x00000022,
        VIDEO = 0x00000023,
        VIRTUAL_DISK = 0x00000024,
        WAVE_IN = 0x00000025,
        WAVE_OUT = 0x00000026,
        PORT_8042 = 0x00000027,
        NETWORK_REDIRECTOR = 0x00000028,
        BATTERY = 0x00000029,
        BUS_EXTENDER = 0x0000002a,
        MODEM = 0x0000002b,
        VDM = 0x0000002c,
        MASS_STORAGE = 0x0000002d,
        SMB = 0x0000002e,
        KS = 0x0000002f,
        CHANGER = 0x00000030,
        SMARTCARD = 0x00000031,
        ACPI = 0x00000032,
        DVD = 0x00000033,
        FULLSCREEN_VIDEO = 0x00000034,
        DFS_FILE_SYSTEM = 0x00000035,
        DFS_VOLUME = 0x00000036,
        SERENUM = 0x00000037,
        TERMSRV = 0x00000038,
        KSEC = 0x00000039,
        FIPS = 0x0000003a,
        INFINIBAND = 0x0000003B,
        VMBUS = 0x0000003E,
        CRYPT_PROVIDER = 0x0000003F,
        WPD = 0x00000040,
        BLUETOOTH = 0x00000041,
        MT_COMPOSITE = 0x00000042,
        MT_TRANSPORT = 0x00000043,
        BIOMETRIC = 0x00000044,
        PMI = 0x00000045,
        EHSTOR = 0x00000046,
        DEVAPI = 0x00000047,
        GPIO = 0x00000048,
        USBEX = 0x00000049,
        MOUNTDEV = 0x0000004D,
        CONSOLE = 0x00000050,
        NFP = 0x00000051,
        SYSENV = 0x00000052,
        VIRTUAL_BLOCK = 0x00000053,
        POINT_OF_SERVICE = 0x00000054,
        STORAGE_REPLICATION = 0x00000055,
        TRUST_ENV = 0x00000056,
        UCM = 0x00000057,
        UCMTCPCI = 0x00000058,
        PERSISTENT_MEMORY = 0x00000059,
        NVDIMM = 0x0000005a,
        HOLOGRAPHIC = 0x0000005b,
        SDFXHCI = 0x0000005c,
        MOUNTMGR = 0x0000006D,
    }

    [Flags]
    public enum FileDeviceCharacteristics
    {
        None = 0,
        RemovableMedia = 0x00000001,
        ReadOnlyDevice = 0x00000002,
        FloppyDiskette = 0x00000004,
        WriteOnceMedia = 0x00000008,
        RemoteDevice = 0x00000010,
        DeviceIsMounted = 0x00000020,
        VirtualVolume = 0x00000040,
        AutoGeneratedName = 0x00000080,
        SecureOpen = 0x00000100,
        PnpDevice = 0x00000800,
        TsDevice = 0x00001000,
        WebDavDevice = 0x00002000,
        PortableDevice = 0x0004000,
        AllowAppContainerTraversal = 0x00020000
    }

    [StructLayout(LayoutKind.Sequential)]
    public class FileFsDeviceInformation
    {
        public FileDeviceType DeviceType;
        public FileDeviceCharacteristics Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class IoStatus
    {
        public UIntPtr Pointer;
        public IntPtr Information;

        public NtStatus Status
        {
            get
            {
                return (NtStatus)(uint)Pointer.ToUInt64();
            }
        }

        /// <summary>
        /// Return the status information field. (32 bit)
        /// </summary>
        /// <exception cref="NtException">Thrown if not complete.</exception>
        internal int Information32
        {
            get
            {
                return Information.ToInt32();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IoStatusStruct
    {
        public UIntPtr Pointer;
        public IntPtr Information;
    }

    [Flags]
    public enum FileShareMode
    {
        None = 0,
        Read = 0x00000001,
        Write = 0x00000002,
        Delete = 0x00000004,
        All = Read | Write | Delete,
    }

    [Flags]
    public enum FileOpenOptions
    {
        None = 0,
        DirectoryFile = 0x00000001,
        WriteThrough = 0x00000002,
        SequentialOnly = 0x00000004,
        NoIntermediateBuffering = 0x00000008,
        SynchronousIoAlert = 0x00000010,
        SynchronousIoNonAlert = 0x00000020,
        NonDirectoryFile = 0x00000040,
        CreateTreeConnection = 0x00000080,
        CompleteIfOplocked = 0x00000100,
        NoEaKnowledge = 0x00000200,
        OpenRemoteInstance = 0x00000400,
        RandomAccess = 0x00000800,
        DeleteOnClose = 0x00001000,
        OpenByFileId = 0x00002000,
        OpenForBackupIntent = 0x00004000,
        NoCompression = 0x00008000,
        OpenRequiringOplock = 0x00010000,
        DisallowExclusive = 0x00020000,
        SessionAware = 0x00040000,
        ReserveOpfilter = 0x00100000,
        OpenReparsePoint = 0x00200000,
        OpenNoRecall = 0x00400000,
        OpenForFreeSpaceQuery = 0x00800000
    }

    [Flags]
    public enum FileAccessRights : uint
    {
        None = 0,
        ReadData = 0x0001,
        WriteData = 0x0002,
        AppendData = 0x0004,
        ReadEa = 0x0008,
        WriteEa = 0x0010,
        Execute = 0x0020,
        DeleteChild = 0x0040,
        ReadAttributes = 0x0080,
        WriteAttributes = 0x0100,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    [Flags]
    public enum FileDirectoryAccessRights : uint
    {
        None = 0,
        ListDirectory = 0x0001,
        AddFile = 0x0002,
        AddSubDirectory = 0x0004,
        ReadEa = 0x0008,
        WriteEa = 0x0010,
        Traverse = 0x0020,
        DeleteChild = 0x0040,
        ReadAttributes = 0x0080,
        WriteAttributes = 0x0100,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Name")]
    public struct FileNameInformation
    {
        public int NameLength;
        public char Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileBasicInformation
    {
        public LargeIntegerStruct CreationTime;
        public LargeIntegerStruct LastAccessTime;
        public LargeIntegerStruct LastWriteTime;
        public LargeIntegerStruct ChangeTime;
        public FileAttributes FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileEndOfFileInformation
    {
        public LargeIntegerStruct EndOfFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileValidDataLengthInformation
    {
        public LargeIntegerStruct ValidDataLength;
    }

    public enum CompressionFormat
    {
        None,
        Default,
        LZNT1,
        XPress,
        XPressHuff
    }

    public enum FileTypeMask
    {
        All = 0,
        FilesOnly = 1,
        DirectoriesOnly = 2,
    }

    public class FileDirectoryEntry
    {
        public int FileIndex { get; private set; }
        public DateTime CreationTime { get; private set; }
        public DateTime LastAccessTime { get; private set; }
        public DateTime LastWriteTime { get; private set; }
        public DateTime ChangeTime { get; private set; }
        public long EndOfFile { get; private set; }
        public long AllocationSize { get; private set; }
        public FileAttributes Attributes { get; private set; }
        public string FileName { get; private set; }

        public bool HasAttributes(FileAttributes attributes)
        {
            return (Attributes & attributes) != 0;
        }

        public bool IsDirectory
        {
            get
            {
                return HasAttributes(FileAttributes.Directory);
            }
        }

        public bool IsReparsePoint
        {
            get
            {
                return HasAttributes(FileAttributes.ReparsePoint);
            }
        }

        internal FileDirectoryEntry(FileDirectoryInformation dir_info, string file_name)
        {
            FileIndex = dir_info.FileIndex;
            CreationTime = DateTime.FromFileTime(dir_info.CreationTime.QuadPart);
            LastAccessTime = DateTime.FromFileTime(dir_info.LastAccessTime.QuadPart);
            LastWriteTime = DateTime.FromFileTime(dir_info.LastWriteTime.QuadPart);
            ChangeTime = DateTime.FromFileTime(dir_info.ChangeTime.QuadPart);
            EndOfFile = dir_info.EndOfFile.QuadPart;
            AllocationSize = dir_info.AllocationSize.QuadPart;
            Attributes = dir_info.FileAttributes;
            FileName = file_name;
        }
    }

    internal sealed class NtAsyncResult : IDisposable
    {
        private NtObject _object;
        private NtEvent _event;
        private SafeIoStatusBuffer _io_status;
        private IoStatus _result;

        internal NtAsyncResult(NtObject @object)
        {
            _object = @object;
            if (!_object.CanSynchronize)
            {
                _event = NtEvent.Create(null,
                    EventType.SynchronizationEvent, false);
            }
            _io_status = new SafeIoStatusBuffer();
            _result = null;
        }

        internal SafeKernelObjectHandle EventHandle
        {
            get { return _event.GetHandle(); }
        }

        internal NtStatus CompleteCall(NtStatus status)
        {
            if (status == NtStatus.STATUS_PENDING)
            {
                if (WaitForComplete())
                {
                    status = _io_status.Result.Status;
                }
            }
            else if (status.IsSuccess())
            {
                _result = _io_status.Result;
            }
            return status;
        }

        internal async Task<NtStatus> CompleteCallAsync(NtStatus status, CancellationToken token)
        {
            try
            {
                if (status == NtStatus.STATUS_PENDING)
                {
                    if (await WaitForCompleteAsync(token))
                    {
                        return _result.Status;
                    }
                }
                else if (status.IsSuccess())
                {
                    _result = _io_status.Result;
                }
                return status;
            }
            catch (TaskCanceledException)
            {
                // Cancel and then rethrow.
                Cancel();
                throw;
            }
        }

        /// <summary>
        /// Wait for the result to complete. This could be waiting on an event
        /// or the file handle.
        /// </summary>
        /// <returns>Returns true if the wait completed successfully.</returns>
        /// <remarks>If true is returned then status and information can be read out.</remarks>
        internal bool WaitForComplete()
        {
            if (_result != null)
            {
                return true;
            }

            NtStatus status;
            if (_event != null)
            {
                status = _event.Wait(NtWaitTimeout.Infinite).ToNtException();
            }
            else
            {
                status = _object.Wait(NtWaitTimeout.Infinite).ToNtException();
            }

            if (status == NtStatus.STATUS_SUCCESS)
            {
                _result = _io_status.Result;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Wait for the result to complete asynchronously. This could be waiting on an event
        /// or the file handle.
        /// </summary>
        /// <param name="token">Cancellation token.</param>
        /// <returns>Returns true if the wait completed successfully.</returns>
        /// <remarks>If true is returned then status and information can be read out.</remarks>
        internal async Task<bool> WaitForCompleteAsync(CancellationToken token)
        {
            if (_result != null)
            {
                return true;
            }

            bool success;

            using (NtWaitHandle wait_handle = _event != null ? _event.DuplicateAsWaitHandle() : _object.DuplicateAsWaitHandle())
            {
                success = await wait_handle.WaitAsync(Timeout.Infinite, token);
            }

            if (success)
            {
                _result = _io_status.Result;
                return true;
            }

            return false;
        }

        private IoStatus GetIoStatus()
        {
            if (_result == null)
            {
                throw new NtException(NtStatus.STATUS_PENDING);
            }
            return _result;
        }

        /// <summary>
        /// Return the status information field.
        /// </summary>
        /// <exception cref="NtException">Thrown if not complete.</exception>
        internal long Information
        {
            get
            {
                return GetIoStatus().Information.ToInt64();
            }
        }

        /// <summary>
        /// Return the status information field. (32 bit)
        /// </summary>
        /// <exception cref="NtException">Thrown if not complete.</exception>
        internal int Information32
        {
            get
            {
                return GetIoStatus().Information.ToInt32();
            }
        }

        /// <summary>
        /// Get completion status code.
        /// </summary>
        /// <exception cref="NtException">Thrown if not complete.</exception>
        internal NtStatus Status
        {
            get
            {
                return GetIoStatus().Status;
            }
        }

        internal IoStatus Result
        {
            get
            {
                return GetIoStatus();
            }
        }

        /// <summary>
        /// Returns true if the call is pending.
        /// </summary>
        internal bool IsPending
        {
            get
            {
                return _result == null;
            }
        }

        internal SafeIoStatusBuffer IoStatusBuffer
        {
            get { return _io_status; }
        }

        /// <summary>
        /// Dispose object.
        /// </summary>
        public void Dispose()
        {
            if (_event != null)
            {
                _event.Close();
            }

            if (_io_status != null)
            {
                _io_status.Close();
            }
        }

        /// <summary>
        /// Reset the file result so it can be reused.
        /// </summary>
        internal void Reset()
        {
            _result = null;
            if (_event != null)
            {
                _event.Clear();
            }
        }

        /// <summary>
        /// Cancel the pending IO operation.
        /// </summary>
        internal void Cancel()
        {
            if (_object is NtFile)
            {
                IoStatus io_status = new IoStatus();
                NtSystemCalls.NtCancelIoFileEx(_object.Handle,
                    _io_status, io_status).ToNtException();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential), DataStart("FileName")]
    public struct FileLinkEntryInformation
    {
        public int NextEntryOffset;
        public long ParentFileId;
        public int FileNameLength;
        public char FileName;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Entry")]
    public struct FileLinksInformation
    {
        public int BytesNeeded;
        public int EntriesReturned;
        public FileLinkEntryInformation Entry;
    }

    public class FileLinkEntry
    {
        public long ParentFileId { get; private set; }
        public string FileName { get; private set; }
        public string FullPath { get; private set; }

        internal FileLinkEntry(SafeStructureInOutBuffer<FileLinkEntryInformation> buffer, string parent_path)
        {
            FileLinkEntryInformation entry = buffer.Result;
            ParentFileId = entry.ParentFileId;
            FileName = buffer.Data.ReadUnicodeString(entry.FileNameLength);
            FullPath = Path.Combine(parent_path, FileName);
        }
    }

    [StructLayout(LayoutKind.Sequential), DataStart("StreamName")]
    public struct FileStreamInformation
    {
        public int NextEntryOffset;
        public int StreamNameLength;
        public LargeIntegerStruct StreamSize;
        public LargeIntegerStruct StreamAllocationSize;
        public char StreamName;
    }

    public class FileStreamEntry
    {
        public long Size { get; private set; }
        public long AllocationSize { get; private set; }
        public string Name { get; private set; }

        internal FileStreamEntry(SafeStructureInOutBuffer<FileStreamInformation> stream)
        {
            var result = stream.Result;
            Size = result.StreamSize.QuadPart;
            AllocationSize = result.StreamAllocationSize.QuadPart;
            Name = stream.Data.ReadUnicodeString(result.StreamNameLength / 2);
        }
    }

    [StructLayout(LayoutKind.Sequential), DataStart("ProcessIdList")]
    public struct FileProcessIdsUsingFileInformation
    {
        public int NumberOfProcessIdsInList;
        public IntPtr ProcessIdList;
    }

    public enum OplockRequestLevel
    {
        Level1,
        Level2,
        Batch,
        Filter
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Sid")]
    public struct FindBySidData
    {
        public int Restart;
        public byte Sid;
    }

    [Flags]
    public enum OplockLevelCache
    {
        None = 0,
        Read = 1,
        Handle = 2,
        Write = 4
    }

    [Flags]
    public enum RequestOplockInputFlag
    {
        None = 0,
        Request = 1,
        Ack = 2,
        CompleteAckOnClose = 4
    }

    [StructLayout(LayoutKind.Sequential)]
    public class RequestOplockInputBuffer
    {
        public ushort StructureVersion;
        public ushort StructureLength;
        public OplockLevelCache RequestedOplockLevel;
        public RequestOplockInputFlag Flags;

        public RequestOplockInputBuffer()
        {
            StructureVersion = 1;
            StructureLength = (ushort)Marshal.SizeOf(typeof(RequestOplockInputBuffer));
        }

        public RequestOplockInputBuffer(OplockLevelCache requested_oplock_level, 
                                        RequestOplockInputFlag flags) : this()
        {
            RequestedOplockLevel = requested_oplock_level;
            Flags = flags;
        }
    }

    [Flags]
    public enum RequestOplockOutputFlag
    {
        None = 0,
        AckRequired = 1,
        ModesProvided = 2
    }

    [StructLayout(LayoutKind.Sequential)]
    public class RequestOplockOutputBuffer
    {
        public ushort StructureVersion;
        public ushort StructureLength;
        public OplockLevelCache OriginalOplockLevel;
        public OplockLevelCache NewOplockLevel;
        public RequestOplockOutputFlag Flags;
        public AccessMask AccessMode;
        public ushort ShareMode;

        public FileAccessRights FileAccessMode => AccessMode.ToSpecificAccess<FileAccessRights>();
        public FileDirectoryAccessRights FileDirectoryAccessMode => AccessMode.ToSpecificAccess<FileDirectoryAccessRights>();
        public FileShareMode FileShareMode => (FileShareMode)ShareMode;

        public RequestOplockOutputBuffer()
        {
            StructureVersion = 1;
            StructureLength = (ushort)Marshal.SizeOf(typeof(RequestOplockOutputBuffer));
        }
    }

    [Flags]
    public enum FileSystemAttributes : uint
    {
        CaseSensitiveSearch = 0x00000001,
        CasePreservedNames = 0x00000002,
        UnicodeOnDisk = 0x00000004,
        PersistentAcls = 0x00000008,
        FileCompression = 0x00000010,
        VolumeQuotas = 0x00000020,
        SupportsSparseFiles = 0x00000040,
        SupportsReparsePoints = 0x00000080,
        SupportsRemoteStorage = 0x00000100,
        ReturnsCleanupResultInfo = 0x00000200,
        SupportsPosixUnlinkRename = 0x00000400,
        Available00000800 = 0x00000800,
        Available00001000 = 0x00001000,
        Available00002000 = 0x00002000,
        Available00004000 = 0x00004000,
        VolumeIsCompressed = 0x00008000,
        SupportsObjectIds = 0x00010000,
        SupportsEncryption = 0x00020000,
        NamedStreams = 0x00040000,
        ReadOnlyVolume = 0x00080000,
        SequentialWriteOnce = 0x00100000,
        SupportsTransactions = 0x00200000,
        SupportsHardLinks = 0x00400000,
        SupportsExtendedAttributes = 0x00800000,
        SupportsOpenByFileId = 0x01000000,
        SupportsUsnJournal = 0x02000000,
        SupportsIntegrityStreams = 0x04000000,
        SupportsBlockRefcounting = 0x08000000,
        SupportsSparseVdl = 0x10000000,
        DaxVolume = 0x20000000,
        SupportsGhosting = 0x40000000,
        Available80000000 = 0x80000000,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("FileSystemName")]
    public struct FileFsAttributeInformation
    {
        public FileSystemAttributes FileSystemAttributes;
        public int MaximumComponentNameLength;
        public int FileSystemNameLength;
        public char FileSystemName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("VolumeLabel")]
    public struct FileFsVolumeInformation
    {
        public LargeIntegerStruct VolumeCreationTime;
        public uint VolumeSerialNumber;
        public int VolumeLabelLength;
        [MarshalAs(UnmanagedType.I1)]
        public bool SupportsObjects;
        public char VolumeLabel;
    }

    public sealed class FileSystemVolumeInformation
    {
        public FileSystemAttributes Attributes { get; }
        public int MaximumComponentLength { get; }
        public string Name { get; }
        public DateTime CreationTime { get; }
        public uint SerialNumber { get; }
        public string Label { get; }
        bool SupportsObjects { get; }

        internal FileSystemVolumeInformation(SafeStructureInOutBuffer<FileFsAttributeInformation> attr_info, 
            SafeStructureInOutBuffer<FileFsVolumeInformation> vol_info)
        {
            var attr_info_res = attr_info.Result;
            var vol_info_res = vol_info.Result;
            Attributes = attr_info_res.FileSystemAttributes;
            MaximumComponentLength = attr_info_res.MaximumComponentNameLength;
            Name = attr_info.Data.ReadUnicodeString(attr_info_res.FileSystemNameLength / 2);

            CreationTime = DateTime.FromFileTime(vol_info_res.VolumeCreationTime.QuadPart);
            SerialNumber = vol_info_res.VolumeSerialNumber;
            SupportsObjects = vol_info_res.SupportsObjects;
            Label = vol_info.Data.ReadUnicodeString(vol_info_res.VolumeLabelLength / 2);
        }
    }


#pragma warning restore 1591

    /// <summary>
    /// Class representing a NT File object
    /// </summary>
    [NtType("File"), NtType("Device")]
    public class NtFile : NtObjectWithDuplicateAndInfo<NtFile, FileAccessRights, FileInformationClass, FileInformationClass>
    {
        #region Constructors

        internal NtFile(SafeKernelObjectHandle handle, IoStatus io_status) : base(handle)
        {
            _cts = new CancellationTokenSource();
            OpenResult = io_status != null ? (FileOpenResult)io_status.Information.ToInt32() : FileOpenResult.Opened;
        }

        internal NtFile(SafeKernelObjectHandle handle)
            : this(handle, null)
        {
        }

        #endregion

        #region Private Members
        // Cancellation source for stopping pending IO on close.
        private CancellationTokenSource _cts;
        private bool? _is_directory;

        private static FileDeviceType GetDeviceType(SafeKernelObjectHandle handle)
        {
            using (var buffer = new SafeStructureInOutBuffer<FileFsDeviceInformation>())
            {
                IoStatus status = new IoStatus();
                var result = NtSystemCalls.NtQueryVolumeInformationFile(handle, status, buffer,
                    buffer.Length, FsInformationClass.FileFsDeviceInformation);
                if (result.IsSuccess())
                {
                    return buffer.Result.DeviceType;
                }
                return FileDeviceType.UNKNOWN;
            }
        }

        private static NtFile CreateFileObject(SafeKernelObjectHandle handle, IoStatus io_status)
        {
            if (GetDeviceType(handle) == FileDeviceType.NAMED_PIPE)
            {
                return new NtNamedPipeFileClient(handle, io_status);
            }
            return new NtFile(handle, io_status);
        }

        private static IntPtr GetSafePointer(SafeBuffer buffer)
        {
            return buffer != null ? buffer.DangerousGetHandle() : IntPtr.Zero;
        }

        private static int GetSafeLength(SafeBuffer buffer)
        {
            return buffer != null ? (int)buffer.ByteLength : 0;
        }

        private delegate NtStatus IoControlFunction(SafeKernelObjectHandle FileHandle,
                                                    SafeKernelObjectHandle Event,
                                                    IntPtr ApcRoutine,
                                                    IntPtr ApcContext,
                                                    SafeIoStatusBuffer IoStatusBlock,
                                                    int IoControlCode,
                                                    IntPtr InputBuffer,
                                                    int InputBufferLength,
                                                    IntPtr OutputBuffer,
                                                    int OutputBufferLength);

        private async Task<NtResult<int>> IoControlGenericAsync(IoControlFunction func,
                        NtIoControlCode control_code, SafeBuffer input_buffer, 
                        SafeBuffer output_buffer, CancellationToken token,
                        bool throw_on_error)
        {
            using (var linked_cts = CancellationTokenSource.CreateLinkedTokenSource(token, _cts.Token))
            {
                using (NtAsyncResult result = new NtAsyncResult(this))
                {
                    NtStatus status = await result.CompleteCallAsync(func(Handle, result.EventHandle, IntPtr.Zero, IntPtr.Zero, result.IoStatusBuffer,
                        control_code.ToInt32(), GetSafePointer(input_buffer), GetSafeLength(input_buffer),
                        GetSafePointer(output_buffer), GetSafeLength(output_buffer)), linked_cts.Token);
                    if (status == NtStatus.STATUS_PENDING)
                    {
                        result.Cancel();
                        return NtStatus.STATUS_CANCELLED.CreateResultFromError<int>(throw_on_error);
                    }
                    return status.CreateResult(throw_on_error, () => result.Information32);
                }
            }
        }

        private async Task<NtResult<byte[]>> IoControlGenericAsync(IoControlFunction func, NtIoControlCode control_code, 
            byte[] input_buffer, int max_output, CancellationToken token, bool throw_on_error)
        {
            using (SafeHGlobalBuffer input = input_buffer != null ? new SafeHGlobalBuffer(input_buffer) : null)
            {
                using (SafeHGlobalBuffer output = max_output > 0 ? new SafeHGlobalBuffer(max_output) : null)
                {
                    var result = await IoControlGenericAsync(func, control_code, input, output, token, true);
                    return result.Map(r => output != null ? output.ReadBytes(r) : new byte[0]);
                }
            }
        }

        private NtResult<int> IoControlGeneric(IoControlFunction func, NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer, bool throw_on_error)
        {
            using (NtAsyncResult result = new NtAsyncResult(this))
            {
                return result.CompleteCall(func(Handle, result.EventHandle, IntPtr.Zero, IntPtr.Zero, result.IoStatusBuffer,
                    control_code.ToInt32(), GetSafePointer(input_buffer), GetSafeLength(input_buffer), GetSafePointer(output_buffer),
                    GetSafeLength(output_buffer))).CreateResult(throw_on_error, () => result.Information32);
            }
        }

        private NtResult<byte[]> IoControlGeneric(IoControlFunction func, NtIoControlCode control_code, byte[] input_buffer, int max_output, bool throw_on_error)
        {
            using (SafeHGlobalBuffer input = input_buffer != null ? new SafeHGlobalBuffer(input_buffer) : null)
            {
                using (SafeHGlobalBuffer output = max_output > 0 ? new SafeHGlobalBuffer(max_output) : null)
                {
                    var result = IoControlGeneric(func, control_code, input, output, throw_on_error);
                    if (result.IsSuccess && output != null)
                    {
                        return new NtResult<byte[]>(result.Status, output.ReadBytes(result.Result));
                    }
                    return new NtResult<byte[]>(result.Status, new byte[0]);
                }
            }
        }

        private void DoRenameEx(string filename, NtFile root, FileRenameInformationExFlags flags)
        {
            FileRenameInformationEx information = new FileRenameInformationEx
            {
                Flags = flags,
                RootDirectory = root.GetHandle().DangerousGetHandle()
            };
            char[] chars = filename.ToCharArray();
            information.FileNameLength = chars.Length * 2;
            using (var buffer = information.ToBuffer(information.FileNameLength, true))
            {
                buffer.Data.WriteArray(0, chars, 0, chars.Length);
                SetBuffer(FileInformationClass.FileRenameInformationEx, buffer);
            }
        }

        private void DoLinkRename(FileInformationClass file_info, string linkname, NtFile root, bool replace_if_exists)
        {
            FileLinkRenameInformation link = new FileLinkRenameInformation
            {
                ReplaceIfExists = replace_if_exists,
                RootDirectory = root.GetHandle().DangerousGetHandle()
            };
            char[] chars = linkname.ToCharArray();
            link.FileNameLength = chars.Length * 2;
            using (var buffer = link.ToBuffer(link.FileNameLength, true))
            {
                buffer.Data.WriteArray(0, chars, 0, chars.Length);
                SetBuffer(file_info, buffer);
            }
        }

        private void DoLinkRename(FileInformationClass file_info, string linkname, NtFile root)
        {
            DoLinkRename(file_info, linkname, root, true);
        }

        private async Task<NtResult<IoStatus>> RunFileCallAsync(Func<NtAsyncResult, NtStatus> func, CancellationToken token, bool throw_on_error)
        {
            using (var linked_cts = CancellationTokenSource.CreateLinkedTokenSource(token, _cts.Token))
            {
                using (NtAsyncResult result = new NtAsyncResult(this))
                {
                    NtStatus status = await result.CompleteCallAsync(func(result), linked_cts.Token);
                    if (status == NtStatus.STATUS_PENDING)
                    {
                        result.Cancel();
                        return NtStatus.STATUS_CANCELLED.CreateResultFromError<IoStatus>(throw_on_error);
                    }
                    return status.CreateResult(throw_on_error, () => result.Result);
                }
            }
        }

        private bool VisitFileEntry(string filename, bool directory, Func<NtFile, bool> visitor, FileAccessRights desired_access,
                                    FileShareMode share_access, FileOpenOptions open_options)
        {
            using (ObjectAttributes obja = new ObjectAttributes(filename, AttributeFlags.CaseInsensitive, this))
            {
                using (var result = Open(obja, desired_access, share_access, open_options, false))
                {
                    if (!result.IsSuccess)
                    {
                        return true;
                    }

                    result.Result._is_directory = directory;
                    return visitor(result.Result);
                }
            }
        }

        private T QueryVolumeFixed<T>(FsInformationClass info_class) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                IoStatus status = new IoStatus();
                NtSystemCalls.NtQueryVolumeInformationFile(Handle, status, buffer,
                    buffer.Length, info_class).ToNtException();
                return buffer.Result;
            }
        }

        private SafeStructureInOutBuffer<T> QueryVolume<T>(FsInformationClass info_class) where T : new()
        {
            SafeStructureInOutBuffer<T> ret = null;
            NtStatus status = NtStatus.STATUS_BUFFER_TOO_SMALL;
            try
            {
                int length = Marshal.SizeOf(typeof(T)) + 128;
                while (true)
                {
                    ret = new SafeStructureInOutBuffer<T>(length, false);
                    IoStatus io_status = new IoStatus();
                    status = NtSystemCalls.NtQueryVolumeInformationFile(Handle, io_status, ret, ret.Length, info_class);
                    if (status.IsSuccess())
                        break;

                    if ((status != NtStatus.STATUS_BUFFER_OVERFLOW) && (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH))
                        throw new NtException(status);
                    ret.Close();
                    length *= 2;
                }
            }
            finally
            {
                if (ret != null && !status.IsSuccess())
                {
                    ret.Close();
                    ret = null;
                }
            }
            return ret;
        }

        private static SafeFileHandle DuplicateAsFile(SafeKernelObjectHandle handle)
        {
            using (SafeKernelObjectHandle dup_handle = DuplicateHandle(handle))
            {
                SafeFileHandle ret = new SafeFileHandle(dup_handle.DangerousGetHandle(), true);
                dup_handle.SetHandleAsInvalid();
                return ret;
            }
        }

        private string TryGetName(FileInformationClass info_class)
        {
            using (var buffer = new SafeStructureInOutBuffer<FileNameInformation>(32 * 1024, true))
            {
                IoStatus status = new IoStatus();
                NtSystemCalls.NtQueryInformationFile(Handle,
                    status, buffer, buffer.Length, info_class).ToNtException();
                char[] result = new char[buffer.Result.NameLength / 2];
                buffer.Data.ReadArray(0, result, 0, result.Length);
                return new string(result);
            }
        }

        private void SetName(FileInformationClass info_class, string name)
        {
            byte[] data = Encoding.Unicode.GetBytes(name);
            FileNameInformation info = new FileNameInformation() { NameLength = data.Length };
            using (var buffer = new SafeStructureInOutBuffer<FileNameInformation>(info, data.Length, true))
            {
                buffer.Data.WriteBytes(data);
                SetBuffer(info_class, buffer);
            }
        }

        private static NtIoControlCode GetOplockFsctl(OplockRequestLevel level)
        {
            switch (level)
            {
                case OplockRequestLevel.Level1:
                    return NtWellKnownIoControlCodes.FSCTL_REQUEST_OPLOCK_LEVEL_1;
                case OplockRequestLevel.Level2:
                    return NtWellKnownIoControlCodes.FSCTL_REQUEST_OPLOCK_LEVEL_2;
                case OplockRequestLevel.Batch:
                    return NtWellKnownIoControlCodes.FSCTL_REQUEST_BATCH_OPLOCK;
                case OplockRequestLevel.Filter:
                    return NtWellKnownIoControlCodes.FSCTL_REQUEST_FILTER_OPLOCK;
                default:
                    throw new ArgumentException("Invalid oplock request level", "level");
            }
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Create a new file
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="file_attributes">Attributes for the file</param>
        /// <param name="share_access">Share access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="disposition">Disposition when opening the file</param>
        /// <param name="ea_buffer">Extended Attributes buffer</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtFile> Create(ObjectAttributes obj_attributes, FileAccessRights desired_access, FileAttributes file_attributes, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer, bool throw_on_error)
        {
            IoStatus iostatus = new IoStatus();
            byte[] buffer = ea_buffer?.ToByteArray();
            return NtSystemCalls.NtCreateFile(out SafeKernelObjectHandle handle, desired_access, obj_attributes, iostatus, null, FileAttributes.Normal,
                share_access, disposition, open_options,
                buffer, buffer != null ? buffer.Length : 0).CreateResult(throw_on_error, () => CreateFileObject(handle, iostatus));
        }

        /// <summary>
        /// Create a new file
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="file_attributes">Attributes for the file</param>
        /// <param name="share_access">Share access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="disposition">Disposition when opening the file</param>
        /// <param name="ea_buffer">Extended Attributes buffer</param>
        /// <returns>The created/opened file object.</returns>
        public static NtFile Create(ObjectAttributes obj_attributes, FileAccessRights desired_access, FileAttributes file_attributes, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer)
        {
            return Create(obj_attributes, desired_access, file_attributes, share_access, open_options, disposition, ea_buffer, true).Result;
        }

        /// <summary>
        /// Create a new file
        /// </summary>
        /// <param name="name">The path to the file</param>
        /// <param name="root">A root object to parse relative filenames</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="file_attributes">Attributes for the file</param>
        /// <param name="share_access">Share access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="disposition">Disposition when opening the file</param>
        /// <param name="ea_buffer">Extended Attributes buffer</param>
        /// <returns>The created/opened file object.</returns>
        public static NtFile Create(string name, NtObject root, FileAccessRights desired_access, FileAttributes file_attributes, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, desired_access, file_attributes, share_access, open_options, disposition, ea_buffer);
            }
        }

        /// <summary>
        /// Create a new file
        /// </summary>
        /// <param name="name">The path to the file</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="share_access">Share access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="disposition">Disposition when opening the file</param>
        /// <param name="ea_buffer">Extended Attributes buffer</param>
        /// <returns>The created/opened file object.</returns>
        public static NtFile Create(string name, FileAccessRights desired_access, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer)
        {
            return Create(name, null, desired_access, FileAttributes.Normal, share_access, open_options, disposition, ea_buffer);
        }

        /// <summary>
        /// Create a new named pipe file
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="share_access">Share access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="disposition">Disposition when opening the file</param>
        /// <param name="completion_mode">Pipe completion mode</param>
        /// <param name="default_timeout">Default timeout</param>
        /// <param name="input_quota">Input quota</param>
        /// <param name="maximum_instances">Maximum number of instances (-1 for infinite)</param>
        /// <param name="output_quota">Output quota</param>
        /// <param name="pipe_type">Type of pipe to create</param>
        /// <param name="read_mode">Pipe read mode</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtNamedPipeFile> CreateNamedPipe(ObjectAttributes obj_attributes, FileAccessRights desired_access,
            FileShareMode share_access, FileOpenOptions open_options, FileDisposition disposition, NamedPipeType pipe_type,
            NamedPipeReadMode read_mode, NamedPipeCompletionMode completion_mode, int maximum_instances, int input_quota,
            int output_quota, NtWaitTimeout default_timeout, bool throw_on_error)
        {
            IoStatus io_status = new IoStatus();
            return NtSystemCalls.NtCreateNamedPipeFile(out SafeKernelObjectHandle handle, desired_access, obj_attributes, io_status, share_access, disposition, open_options,
                pipe_type, read_mode, completion_mode, maximum_instances, input_quota, output_quota, default_timeout.ToLargeInteger())
                .CreateResult(throw_on_error, () => new NtNamedPipeFile(handle, io_status));
        }

        /// <summary>
        /// Create a new named pipe file
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="share_access">Share access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="disposition">Disposition when opening the file</param>
        /// <param name="completion_mode">Pipe completion mode</param>
        /// <param name="default_timeout">Default timeout</param>
        /// <param name="input_quota">Input quota</param>
        /// <param name="maximum_instances">Maximum number of instances (-1 for infinite)</param>
        /// <param name="output_quota">Output quota</param>
        /// <param name="pipe_type">Type of pipe to create</param>
        /// <param name="read_mode">Pipe read mode</param>
        /// <returns>The file instance for the pipe.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtNamedPipeFile CreateNamedPipe(ObjectAttributes obj_attributes, FileAccessRights desired_access,
            FileShareMode share_access, FileOpenOptions open_options, FileDisposition disposition, NamedPipeType pipe_type,
            NamedPipeReadMode read_mode, NamedPipeCompletionMode completion_mode, int maximum_instances, int input_quota,
            int output_quota, NtWaitTimeout default_timeout)
        {
            return CreateNamedPipe(obj_attributes, desired_access, share_access, open_options, disposition, pipe_type,
                read_mode, completion_mode, maximum_instances, input_quota, output_quota, default_timeout, true).Result;
        }

        /// <summary>
        /// Create a new named pipe file
        /// </summary>
        /// <param name="name">The path to the pipe file</param>
        /// <param name="root">A root object to parse relative filenames</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="share_access">Share access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="disposition">Disposition when opening the file</param>
        /// <param name="completion_mode">Pipe completion mode</param>
        /// <param name="default_timeout">Default timeout</param>
        /// <param name="input_quota">Input quota</param>
        /// <param name="maximum_instances">Maximum number of instances (-1 for infinite)</param>
        /// <param name="output_quota">Output quota</param>
        /// <param name="pipe_type">Type of pipe to create</param>
        /// <param name="read_mode">Pipe read mode</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The file instance for the pipe.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtNamedPipeFile> CreateNamedPipe(string name, NtObject root, FileAccessRights desired_access,
            FileShareMode share_access, FileOpenOptions open_options, FileDisposition disposition, NamedPipeType pipe_type,
            NamedPipeReadMode read_mode, NamedPipeCompletionMode completion_mode, int maximum_instances, int input_quota,
            int output_quota, NtWaitTimeout default_timeout, bool throw_on_error)
        {
            using (ObjectAttributes obj_attributes = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return CreateNamedPipe(obj_attributes, desired_access, share_access, open_options, disposition, pipe_type,
                    read_mode, completion_mode, maximum_instances, input_quota, output_quota, default_timeout, throw_on_error);
            }
        }

        /// <summary>
        /// Create a new named pipe file
        /// </summary>
        /// <param name="name">The path to the pipe file</param>
        /// <param name="root">A root object to parse relative filenames</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="share_access">Share access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="disposition">Disposition when opening the file</param>
        /// <param name="completion_mode">Pipe completion mode</param>
        /// <param name="default_timeout">Default timeout</param>
        /// <param name="input_quota">Input quota</param>
        /// <param name="maximum_instances">Maximum number of instances (-1 for infinite)</param>
        /// <param name="output_quota">Output quota</param>
        /// <param name="pipe_type">Type of pipe to create</param>
        /// <param name="read_mode">Pipe read mode</param>
        /// <returns>The file instance for the pipe.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtNamedPipeFile CreateNamedPipe(string name, NtObject root, FileAccessRights desired_access,
            FileShareMode share_access, FileOpenOptions open_options, FileDisposition disposition, NamedPipeType pipe_type,
            NamedPipeReadMode read_mode, NamedPipeCompletionMode completion_mode, int maximum_instances, int input_quota,
            int output_quota, NtWaitTimeout default_timeout)
        {
            return CreateNamedPipe(name, root, desired_access, share_access, open_options, disposition, pipe_type,
                  read_mode, completion_mode, maximum_instances, input_quota, output_quota, default_timeout, true).Result;
        }

        /// <summary>
        /// Create an anonymous named pipe pair.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The named pipe pair.</returns>
        public static NtResult<NtNamedPipeFilePair> CreatePipePair(bool throw_on_error)
        {
            using (var np_dir = Open(@"\Device\NamedPipe\", null,
                FileAccessRights.Synchronize | FileAccessRights.GenericRead,
                FileShareMode.Read | FileShareMode.Write, FileOpenOptions.SynchronousIoNonAlert, throw_on_error))
            {
                if (!np_dir.IsSuccess)
                {
                    return np_dir.Status.CreateResultFromError<NtNamedPipeFilePair>(false);
                }
                using (var list = new DisposableList())
                {
                    var read_pipe = list.AddResource(CreateNamedPipe(string.Empty, np_dir.Result, FileAccessRights.GenericRead | FileAccessRights.Synchronize | FileAccessRights.WriteAttributes,
                        FileShareMode.Read | FileShareMode.Write, FileOpenOptions.SynchronousIoNonAlert, FileDisposition.Create,
                        NamedPipeType.Bytestream, NamedPipeReadMode.ByteStream, NamedPipeCompletionMode.QueueOperation,
                        1, 4096, 4096, new NtWaitTimeout(-1200000000), false));
                    if (!read_pipe.IsSuccess)
                    {
                        return read_pipe.Status.CreateResultFromError<NtNamedPipeFilePair>(false);
                    }

                    var write_pipe = list.AddResource(Open(string.Empty, read_pipe.Result, FileAccessRights.GenericWrite | FileAccessRights.Synchronize | FileAccessRights.ReadAttributes,
                        FileShareMode.Read | FileShareMode.Write, FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.NonDirectoryFile, false));
                    if (!write_pipe.IsSuccess)
                    {
                        return write_pipe.Status.CreateResultFromError<NtNamedPipeFilePair>(false);
                    }

                    list.Clear();
                    return new NtResult<NtNamedPipeFilePair>(NtStatus.STATUS_SUCCESS, new NtNamedPipeFilePair(read_pipe.Result, write_pipe.Result as NtNamedPipeFileClient));
                }
            }
        }

        /// <summary>
        /// Create an anonymous named pipe pair.
        /// </summary>
        /// <returns>The named pipe pair.</returns>
        public static NtNamedPipeFilePair CreatePipePair()
        {
            return CreatePipePair(true).Result;
        }

        /// <summary>
        /// Create a new named mailslot file
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="mailslot_quota">Mailslot quota</param>
        /// <param name="maximum_message_size">Maximum message size (0 for any size)</param>
        /// <param name="default_timeout">Timeout in MS ( &lt;0 is infinite)</param>
        /// <returns>The file instance for the mailslot.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtFile CreateMailslot(ObjectAttributes obj_attributes, FileAccessRights desired_access,
            FileOpenOptions open_options, int maximum_message_size, int mailslot_quota,
            long default_timeout)
        {
            IoStatus io_status = new IoStatus();
            LargeInteger timeout = default_timeout < 0 ? new LargeInteger(-1) : NtWaitTimeout.FromMilliseconds(default_timeout).ToLargeInteger();
            NtSystemCalls.NtCreateMailslotFile(out SafeKernelObjectHandle handle, desired_access, obj_attributes, io_status, open_options, mailslot_quota, maximum_message_size, timeout);
            return new NtFile(handle, io_status);
        }

        /// <summary>
        /// Create a new named mailslot file
        /// </summary>
        /// <param name="name">The path to the mailslot file</param>
        /// <param name="root">A root object to parse relative filenames</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="mailslot_quota">Mailslot quota</param>
        /// <param name="maximum_message_size">Maximum message size (0 for any size)</param>
        /// <param name="default_timeout">Timeout in MS ( &lt;0 is infinite)</param>
        /// <returns>The file instance for the mailslot.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtFile CreateMailslot(string name, NtObject root, FileAccessRights desired_access,
            FileOpenOptions open_options, int maximum_message_size, int mailslot_quota,
            long default_timeout)
        {
            using (ObjectAttributes obj_attributes = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return CreateMailslot(obj_attributes, desired_access, open_options, maximum_message_size, mailslot_quota, default_timeout);
            }
        }

        /// <summary>
        /// Open a file
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>
        /// <param name="desired_access">The desired access for the file handle</param>
        /// <param name="share_access">The file share access</param>
        /// <param name="open_options">File open options</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtFile> Open(ObjectAttributes obj_attributes, FileAccessRights desired_access,
            FileShareMode share_access, FileOpenOptions open_options, bool throw_on_error)
        {
            IoStatus iostatus = new IoStatus();
            return NtSystemCalls.NtOpenFile(out SafeKernelObjectHandle handle, desired_access, obj_attributes, iostatus, share_access, open_options)
                .CreateResult(throw_on_error, () => CreateFileObject(handle, iostatus));
        }

        internal static NtResult<NtObject> FromName(ObjectAttributes object_attributes, AccessMask desired_access, bool throw_on_error)
        {
            return Open(object_attributes, desired_access.ToSpecificAccess<FileAccessRights>(), FileShareMode.Read | FileShareMode.Delete,
                FileOpenOptions.None, throw_on_error).Cast<NtObject>();
        }

        /// <summary>
        /// Open a file
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>f
        /// <param name="desired_access">The desired access for the file handle</param>
        /// <param name="share_access">The file share access</param>
        /// <param name="open_options">File open options</param>
        /// <returns>The opened file</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtFile Open(ObjectAttributes obj_attributes, FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options)
        {
            return Open(obj_attributes, desired_access, share_access, open_options, true).Result;
        }

        /// <summary>
        /// Open a file
        /// </summary>
        /// <param name="path">The path to the file</param>
        /// <param name="root">The root directory if path is relative.</param>
        /// <param name="desired_access">The desired access for the file handle</param>
        /// <param name="shared_access">The file share access</param>
        /// <param name="open_options">File open options</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The opened file</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtFile> Open(string path, NtObject root, FileAccessRights desired_access,
            FileShareMode shared_access, FileOpenOptions open_options, bool throw_on_error)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access, shared_access, open_options, throw_on_error);
            }
        }

        /// <summary>
        /// Open a file
        /// </summary>
        /// <param name="path">The path to the file</param>
        /// <param name="root">The root directory if path is relative.</param>
        /// <param name="desired_access">The desired access for the file handle</param>
        /// <param name="shared_access">The file share access</param>
        /// <param name="open_options">File open options</param>
        /// <returns>The opened file</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtFile Open(string path, NtObject root, FileAccessRights desired_access,
            FileShareMode shared_access, FileOpenOptions open_options)
        {
            return Open(path, root, desired_access, shared_access, open_options, true).Result;
        }

        /// <summary>
        /// Open a file
        /// </summary>
        /// <param name="path">The path to the file</param>
        /// <param name="root">The root directory if path is relative.</param>
        /// <param name="desired_access">The desired access for the file handle</param>
        /// <returns>The opened file</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtFile Open(string path, NtObject root, FileAccessRights desired_access)
        {
            return Open(path, root, desired_access,
                FileShareMode.Read | FileShareMode.Delete, FileOpenOptions.None);
        }

        /// <summary>
        /// Get the object ID of a file as a string
        /// </summary>
        /// <param name="path">The path to the file</param>
        /// <returns>The object ID as a string</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static string GetFileId(string path)
        {
            using (NtFile file = Open(path, null, FileAccessRights.MaximumAllowed, FileShareMode.None, FileOpenOptions.None))
            {
                return file.FileId;
            }
        }

        /// <summary>
        /// Open a file by its object ID
        /// </summary>
        /// <param name="volume">A handle to the volume on which the file resides.</param>
        /// <param name="id">The object ID as a binary string</param>
        /// <param name="desired_access">The desired access for the file</param>
        /// <param name="share_access">File share access</param>
        /// <param name="open_options">Open options.</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The opened file object</returns>
        public static NtResult<NtFile> OpenFileById(NtFile volume, string id,
            FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options, bool throw_on_error)
        {
            using (ObjectAttributes obja = new ObjectAttributes(id, AttributeFlags.CaseInsensitive, volume, null, null))
            {
                IoStatus iostatus = new IoStatus();
                return NtSystemCalls.NtOpenFile(out SafeKernelObjectHandle handle, desired_access, obja,
                    iostatus, share_access, open_options | FileOpenOptions.OpenByFileId)
                    .CreateResult(throw_on_error, () => new NtFile(handle, iostatus));
            }
        }

        /// <summary>
        /// Open a file by its object ID
        /// </summary>
        /// <param name="volume">A handle to the volume on which the file resides.</param>
        /// <param name="id">The object ID as a binary string</param>
        /// <param name="desired_access">The desired access for the file</param>
        /// <param name="share_access">File share access</param>
        /// <param name="open_options">Open options.</param>
        /// <returns>The opened file object</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtFile OpenFileById(NtFile volume, string id,
            FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options)
        {
            return OpenFileById(volume, id, desired_access, share_access, open_options, true).Result;
        }

        /// <summary>
        /// Delete a file
        /// </summary>
        /// <param name="obj_attributes">The object attributes for the file.</param>
        /// <param name="throw_on_error">True to throw an exception on error</param>
        /// <returns>The status result of the delete</returns>
        public static NtStatus Delete(ObjectAttributes obj_attributes, bool throw_on_error)
        {
            return NtSystemCalls.NtDeleteFile(obj_attributes).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Delete a file
        /// </summary>
        /// <param name="obj_attributes">The object attributes for the file.</param>
        public static void Delete(ObjectAttributes obj_attributes)
        {
            Delete(obj_attributes, true);
        }

        /// <summary>
        /// Delete a file
        /// </summary>
        /// <param name="path">The path to the file.</param>
        public static void Delete(string path)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path))
            {
                Delete(obja);
            }
        }

        /// <summary>
        /// Rename file.
        /// </summary>
        /// <param name="path">The file to rename.</param>
        /// <param name="new_name">The target NT path.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static void Rename(string path, string new_name)
        {
            using (NtFile file = Open(path, null, FileAccessRights.Delete,
                FileShareMode.Read | FileShareMode.Delete, FileOpenOptions.None))
            {
                file.Rename(new_name);
            }
        }

        /// <summary>
        /// Create a hardlink to another file.
        /// </summary>
        /// <param name="path">The file to hardlink to.</param>
        /// <param name="linkname">The desintation hardlink path.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static void CreateHardlink(string path, string linkname)
        {
            using (NtFile file = Open(path, null, FileAccessRights.MaximumAllowed,
                FileShareMode.Read, FileOpenOptions.NonDirectoryFile))
            {
                file.CreateHardlink(linkname);
            }
        }

        /// <summary>
        /// Create a mount point.
        /// </summary>
        /// <param name="path">The path to the mount point to create.</param>
        /// <param name="substitute_name">The substitute name to reparse to.</param>
        /// <param name="print_name">The print name to display (can be null).</param>
        public static void CreateMountPoint(string path, string substitute_name, string print_name)
        {
            using (NtFile file = Create(path, FileAccessRights.Synchronize | FileAccessRights.MaximumAllowed,
                FileShareMode.None, FileOpenOptions.DirectoryFile | FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenReparsePoint,
                FileDisposition.OpenIf, null))
            {
                file.SetMountPoint(substitute_name, print_name);
            }
        }

        /// <summary>
        /// Create a symlink.
        /// </summary>
        /// <param name="path">The path to the mount point to create.</param>
        /// <param name="directory">True to create a directory symlink, false for a file.</param>
        /// <param name="substitute_name">The substitute name to reparse to.</param>
        /// <param name="print_name">The print name to display.</param>
        /// <param name="flags">Additional flags for the symlink.</param>
        public static void CreateSymlink(string path, bool directory, string substitute_name, string print_name, SymlinkReparseBufferFlags flags)
        {
            using (NtFile file = Create(path, FileAccessRights.Synchronize | FileAccessRights.MaximumAllowed,
                FileShareMode.None, (directory ? FileOpenOptions.DirectoryFile : FileOpenOptions.NonDirectoryFile)
                | FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenReparsePoint,
                FileDisposition.OpenIf, null))
            {
                file.SetSymlink(substitute_name, print_name, flags);
            }
        }

        /// <summary>
        /// Get the reparse point buffer for the file.
        /// </summary>
        /// <param name="path">The path to the reparse point.</param>
        /// <returns>The reparse point buffer.</returns>
        public static ReparseBuffer GetReparsePoint(string path)
        {
            using (NtFile file = Open(path, null, FileAccessRights.Synchronize | FileAccessRights.MaximumAllowed,
                FileShareMode.None, FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenReparsePoint))
            {
                return file.GetReparsePoint();
            }
        }

        /// <summary>
        /// Delete the reparse point buffer.
        /// </summary>
        /// <param name="path">The path to the reparse point.</param>
        /// <returns>The original reparse buffer.</returns>
        public static ReparseBuffer DeleteReparsePoint(string path)
        {
            using (NtFile file = Open(path, null, FileAccessRights.Synchronize | FileAccessRights.MaximumAllowed,
                FileShareMode.None, FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenReparsePoint))
            {
                return file.DeleteReparsePoint();
            }
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Send a Device IO Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <param name="token">Cancellation token to cancel the async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The length of output bytes returned.</returns>
        public Task<NtResult<int>> DeviceIoControlAsync(NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer, CancellationToken token, bool throw_on_error)
        {
            return IoControlGenericAsync(NtSystemCalls.NtDeviceIoControlFile, control_code, input_buffer, output_buffer, token, throw_on_error);
        }

        /// <summary>
        /// Send a Device IO Control code to the file driver.
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="max_output">Maximum output buffer size</param>
        /// <param name="token">Cancellation token to cancel the async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The output buffer returned by the kernel.</returns>
        public Task<NtResult<byte[]>> DeviceIoControlAsync(NtIoControlCode control_code, byte[] input_buffer, int max_output, CancellationToken token, bool throw_on_error)
        {
            return IoControlGenericAsync(NtSystemCalls.NtDeviceIoControlFile, control_code, input_buffer, max_output, token, throw_on_error);
        }

        /// <summary>
        /// Send a Device IO Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <param name="token">Cancellation token to cancel the async operation.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The length of output bytes returned.</returns>
        public Task<int> DeviceIoControlAsync(NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer, CancellationToken token)
        {
            return DeviceIoControlAsync(control_code, input_buffer, output_buffer, token, true).UnwrapNtResultAsync();
        }

        /// <summary>
        /// Send a Device IO Control code to the file driver.
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="max_output">Maximum output buffer size</param>
        /// <param name="token">Cancellation token to cancel the async operation.</param>
        /// <returns>The output buffer returned by the kernel.</returns>
        public Task<byte[]> DeviceIoControlAsync(NtIoControlCode control_code, byte[] input_buffer, int max_output, CancellationToken token)
        {
            return DeviceIoControlAsync(control_code, input_buffer, max_output, token, true).UnwrapNtResultAsync();
        }

        /// <summary>
        /// Send a File System Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <param name="token">Cancellation token to cancel the async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The length of output bytes returned.</returns>
        public Task<NtResult<int>> FsControlAsync(NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer, CancellationToken token, bool throw_on_error)
        {
            return IoControlGenericAsync(NtSystemCalls.NtFsControlFile, control_code, input_buffer, output_buffer, token, throw_on_error);
        }

        /// <summary>
        /// Send a File System Control code to the file driver.
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="max_output">Maximum output buffer size</param>
        /// <param name="token">Cancellation token to cancel the async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The output buffer returned by the kernel.</returns>
        public Task<NtResult<byte[]>> FsControlAsync(NtIoControlCode control_code, byte[] input_buffer, int max_output, CancellationToken token, bool throw_on_error)
        {
            return IoControlGenericAsync(NtSystemCalls.NtFsControlFile, control_code, input_buffer, max_output, token, throw_on_error);
        }

        /// <summary>
        /// Send a File System Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <param name="token">Cancellation token to cancel the async operation.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The length of output bytes returned.</returns>
        public Task<int> FsControlAsync(NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer, CancellationToken token)
        {
            return FsControlAsync(control_code, input_buffer, output_buffer, token, true).UnwrapNtResultAsync();
        }

        /// <summary>
        /// Send a File System Control code to the file driver.
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="max_output">Maximum output buffer size</param>
        /// <param name="token">Cancellation token to cancel the async operation.</param>
        /// <returns>The output buffer returned by the kernel.</returns>
        public Task<byte[]> FsControlAsync(NtIoControlCode control_code, byte[] input_buffer, int max_output, CancellationToken token)
        {
            return FsControlAsync(control_code, input_buffer, max_output, token, true).UnwrapNtResultAsync();
        }

        /// <summary>
        /// Send a Device IO Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The length of output bytes returned.</returns>
        public Task<int> DeviceIoControlAsync(NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer)
        {
            return DeviceIoControlAsync(control_code, input_buffer, output_buffer, CancellationToken.None);
        }

        /// <summary>
        /// Send a Device IO Control code to the file driver.
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="max_output">Maximum output buffer size</param>
        /// <returns>The output buffer returned by the kernel.</returns>
        public Task<byte[]> DeviceIoControlAsync(NtIoControlCode control_code, byte[] input_buffer, int max_output)
        {
            return DeviceIoControlAsync(control_code, input_buffer, max_output, CancellationToken.None);
        }

        /// <summary>
        /// Send a File System Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The length of output bytes returned.</returns>
        public Task<int> FsControlAsync(NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer)
        {
            return FsControlAsync(control_code, input_buffer, output_buffer, CancellationToken.None);
        }

        /// <summary>
        /// Send a File System Control code to the file driver.
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="max_output">Maximum output buffer size</param>
        /// <returns>The output buffer returned by the kernel.</returns>
        public Task<byte[]> FsControlAsync(NtIoControlCode control_code, byte[] input_buffer, int max_output)
        {
            return FsControlAsync(control_code, input_buffer, max_output, CancellationToken.None);
        }

        /// <summary>
        /// Send a Device IO Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The length of output bytes returned.</returns>
        public Task<NtResult<int>> DeviceIoControlAsync(NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer, bool throw_on_error)
        {
            return DeviceIoControlAsync(control_code, input_buffer, output_buffer, CancellationToken.None, throw_on_error);
        }

        /// <summary>
        /// Send a Device IO Control code to the file driver.
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="max_output">Maximum output buffer size</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The output buffer returned by the kernel.</returns>
        public Task<NtResult<byte[]>> DeviceIoControlAsync(NtIoControlCode control_code, byte[] input_buffer, int max_output, bool throw_on_error)
        {
            return DeviceIoControlAsync(control_code, input_buffer, max_output, CancellationToken.None, throw_on_error);
        }

        /// <summary>
        /// Send a File System Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The length of output bytes returned.</returns>
        public Task<NtResult<int>> FsControlAsync(NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer, bool throw_on_error)
        {
            return FsControlAsync(control_code, input_buffer, output_buffer, CancellationToken.None, throw_on_error);
        }

        /// <summary>
        /// Send a File System Control code to the file driver.
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="max_output">Maximum output buffer size</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The output buffer returned by the kernel.</returns>
        public Task<NtResult<byte[]>> FsControlAsync(NtIoControlCode control_code, byte[] input_buffer, int max_output, bool throw_on_error)
        {
            return FsControlAsync(control_code, input_buffer, max_output, CancellationToken.None, throw_on_error);
        }

        /// <summary>
        /// Send a Device IO Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The length of output bytes returned.</returns>
        public NtResult<int> DeviceIoControl(NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer, bool throw_on_error)
        {
            return IoControlGeneric(NtSystemCalls.NtDeviceIoControlFile, control_code, input_buffer, output_buffer, throw_on_error);
        }

        /// <summary>
        /// Send a Device IO Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The length of output bytes returned.</returns>
        public int DeviceIoControl(NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer)
        {
            return DeviceIoControl(control_code, input_buffer, output_buffer, true).Result;
        }

        /// <summary>
        /// Send a Device IO Control code to the file driver.
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="max_output">Maximum output buffer size</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The output buffer returned by the kernel.</returns>
        public NtResult<byte[]> DeviceIoControl(NtIoControlCode control_code, byte[] input_buffer, int max_output, bool throw_on_error)
        {
            return IoControlGeneric(NtSystemCalls.NtDeviceIoControlFile, control_code, input_buffer, max_output, throw_on_error);
        }

        /// <summary>
        /// Send a Device IO Control code to the file driver.
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="max_output">Maximum output buffer size</param>
        /// <returns>The output buffer returned by the kernel.</returns>
        public byte[] DeviceIoControl(NtIoControlCode control_code, byte[] input_buffer, int max_output)
        {
            return DeviceIoControl(control_code, input_buffer, max_output, true).Result;
        }

        /// <summary>
        /// Send an File System Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The length of output bytes returned.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<int> FsControl(NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer, bool throw_on_error)
        {
            return IoControlGeneric(NtSystemCalls.NtFsControlFile, control_code, input_buffer, output_buffer, throw_on_error);
        }

        /// <summary>
        /// Send a File System Control code to the file driver.
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="max_output">Maximum output buffer size</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The output buffer returned by the kernel.</returns>
        public NtResult<byte[]> FsControl(NtIoControlCode control_code, byte[] input_buffer, int max_output, bool throw_on_error)
        {
            return IoControlGeneric(NtSystemCalls.NtFsControlFile, control_code, input_buffer, max_output, throw_on_error);
        }

        /// <summary>
        /// Send an File System Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <returns>The length of output bytes returned.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int FsControl(NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer)
        {
            return FsControl(control_code, input_buffer, output_buffer, true).Result;
        }

        /// <summary>
        /// Send a File System Control code to the file driver.
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="max_output">Maximum output buffer size</param>
        /// <returns>The output buffer returned by the kernel.</returns>
        public byte[] FsControl(NtIoControlCode control_code, byte[] input_buffer, int max_output)
        {
            return FsControl(control_code, input_buffer, max_output, true).Result;
        }

        /// <summary>
        /// Re-open an existing file for different access.
        /// </summary>
        /// <param name="desired_access">The desired access for the file handle</param>
        /// <param name="share_access">The file share access</param>
        /// <param name="open_options">File open options</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<NtFile> ReOpen(FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options, bool throw_on_error)
        {
            using (ObjectAttributes obj_attributes = new ObjectAttributes(String.Empty, AttributeFlags.CaseInsensitive, this))
            {
                return Open(obj_attributes, desired_access, share_access, open_options, throw_on_error);
            }
        }

        /// <summary>
        /// Re-open an exsiting file for different access.
        /// </summary>
        /// <param name="desired_access">The desired access for the file handle</param>
        /// <param name="share_access">The file share access</param>
        /// <param name="open_options">File open options</param>
        /// <returns>The opened file</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtFile ReOpen(FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options)
        {
            return ReOpen(desired_access, share_access, open_options, true).Result;
        }

        /// <summary>
        /// Delete the file. Must have been opened with DELETE access.
        /// </summary>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Delete()
        {
            Set(FileInformationClass.FileDispositionInformation, new FileDispositionInformation() { DeleteFile = true });
        }

        /// <summary>
        /// Delete the file (extended Windows version). Must have been opened with DELETE access.
        /// </summary>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void DeleteEx(FileDispositionInformationExFlags flags)
        {
            Set(FileInformationClass.FileDispositionInformationEx, new FileDispositionInformationEx() { Flags = flags });
        }

        /// <summary>
        /// Create a new hardlink to this file.
        /// </summary>
        /// <param name="linkname">The target NT path.</param>
        /// <param name="root">The root directory if linkname is relative</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void CreateHardlink(string linkname, NtFile root)
        {
            DoLinkRename(FileInformationClass.FileLinkInformation, linkname, root);
        }

        /// <summary>
        /// Create a new hardlink to this file.
        /// </summary>
        /// <param name="linkname">The target absolute NT path.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void CreateHardlink(string linkname)
        {
            DoLinkRename(FileInformationClass.FileLinkInformation, linkname, null);
        }

        /// <summary>
        /// Rename file.
        /// </summary>
        /// <param name="new_name">The target NT path.</param>
        /// <param name="root">The root directory if new_name is relative</param>
        /// <param name="replace_if_exists">If TRUE, replaces the target file if it exists. If FALSE, fails if the target file already exists.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Rename(string new_name, NtFile root, bool replace_if_exists)
        {
            DoLinkRename(FileInformationClass.FileRenameInformation, new_name, root, replace_if_exists);
        }

        /// <summary>
        /// Rename file.
        /// </summary>
        /// <param name="new_name">The target NT path.</param>
        /// <param name="root">The root directory if new_name is relative</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Rename(string new_name, NtFile root)
        {
            Rename(new_name, root, true);
        }

        /// <summary>
        /// Rename this file with an absolute path.
        /// </summary>
        /// <param name="new_name">The target absolute NT path.</param>
        /// <param name="replace_if_exists">If TRUE, replace the target file if it exists. If FALSE, fails if the target file already exists.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Rename(string new_name, bool replace_if_exists)
        {
            DoLinkRename(FileInformationClass.FileRenameInformation, new_name, null, replace_if_exists);
        }

        /// <summary>
        /// Rename this file with an absolute path.
        /// </summary>
        /// <param name="new_name">The target absolute NT path.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Rename(string new_name)
        {
            Rename(new_name, true);
        }

        /// <summary>
        /// Rename (extended Windows version) this file with an absolute path.
        /// </summary>
        /// <param name="new_name">The target absolute NT path.</param>
        /// <param name="flags">The flags associated to FileRenameInformationEx.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void RenameEx(string new_name, FileRenameInformationExFlags flags)
        {
            DoRenameEx(new_name, null, flags);
        }

        /// <summary>
        /// Set an arbitrary reparse point.
        /// </summary>
        /// <param name="reparse">The reparse point data.</param>
        public void SetReparsePoint(ReparseBuffer reparse)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(reparse.ToByteArray()))
            {
                FsControl(NtWellKnownIoControlCodes.FSCTL_SET_REPARSE_POINT, buffer, null);
            }
        }

        /// <summary>
        /// Set a mount point on the current file object.
        /// </summary>
        /// <param name="substitute_name">The substitute name to reparse to.</param>
        /// <param name="print_name">The print name to display (can be null).</param>
        public void SetMountPoint(string substitute_name, string print_name)
        {
            SetReparsePoint(new MountPointReparseBuffer(substitute_name, print_name));
        }

        /// <summary>
        /// Set a symlink on the current file object.
        /// </summary>
        /// <param name="substitute_name">The substitute name to reparse to.</param>
        /// <param name="print_name">The print name to display.</param>
        /// <param name="flags">Additional flags for the symlink.</param>
        public void SetSymlink(string substitute_name, string print_name, SymlinkReparseBufferFlags flags)
        {
            SetReparsePoint(new SymlinkReparseBuffer(substitute_name, print_name, flags));
        }

        /// <summary>
        /// Get the reparse point buffer for the file.
        /// </summary>
        /// <param name="opaque_buffer">If the reparse tag isn't known 
        /// return an opaque buffer, otherwise a generic buffer</param>
        /// <returns>The reparse point buffer.</returns>
        public ReparseBuffer GetReparsePoint(bool opaque_buffer)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(16 * 1024))
            {
                FsControl(NtWellKnownIoControlCodes.FSCTL_GET_REPARSE_POINT, null, buffer);

                return ReparseBuffer.FromByteArray(buffer.ToArray(), opaque_buffer);
            }
        }

        /// <summary>
        /// Get the reparse point buffer for the file.
        /// </summary>
        /// <returns>The reparse point buffer.</returns>
        public ReparseBuffer GetReparsePoint()
        {
            return GetReparsePoint(false);
        }

        /// <summary>
        /// Delete the reparse point buffer
        /// </summary>
        /// <returns>The original reparse buffer.</returns>
        public ReparseBuffer DeleteReparsePoint()
        {
            ReparseBuffer reparse = GetReparsePoint();
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(new OpaqueReparseBuffer(reparse.Tag, new byte[0]).ToByteArray()))
            {
                FsControl(NtWellKnownIoControlCodes.FSCTL_DELETE_REPARSE_POINT, buffer, null);
            }
            return reparse;
        }

        /// <summary>
        /// Get list of accessible files underneath a directory.
        /// </summary>
        /// <param name="share_access">Share access for file open</param>
        /// <param name="open_options">Options for open call.</param>
        /// <param name="desired_access">The desired access for each file.</param>
        /// <param name="file_mask">A file name mask (such as *.txt). Can be null.</param>
        /// <param name="type_mask">Indicate what entries to return.</param>
        /// <returns>The list of files which can be access.</returns>
        public IEnumerable<NtFile> QueryAccessibleFiles(FileAccessRights desired_access, FileShareMode share_access,
            FileOpenOptions open_options, string file_mask, FileTypeMask type_mask)
        {
            using (var list = new DisposableList<NtFile>())
            {
                foreach (var entry in QueryDirectoryInfo(file_mask, type_mask))
                {
                    using (ObjectAttributes obja = new ObjectAttributes(entry.FileName, AttributeFlags.CaseInsensitive, this))
                    {
                        var result = Open(obja, desired_access, share_access, open_options, false);
                        if (result.IsSuccess)
                        {
                            result.Result._is_directory = entry.IsDirectory;
                            list.Add(result.Result);
                        }
                    }
                }
                return new List<NtFile>(list.ToArrayAndClear());
            }
        }

        /// <summary>
        /// Get list of accessible files underneath a directory.
        /// </summary>
        /// <param name="share_access">Share access for file open</param>
        /// <param name="open_options">Options for open call.</param>
        /// <param name="desired_access">The desired access for each file.</param>
        /// <returns>The list of files which can be access.</returns>
        public IEnumerable<NtFile> QueryAccessibleFiles(FileAccessRights desired_access, FileShareMode share_access,
            FileOpenOptions open_options)
        {
            return QueryAccessibleFiles(desired_access, share_access, open_options, null, FileTypeMask.All);
        }

        /// <summary>
        /// Query a directory for files.
        /// </summary>
        /// <returns></returns>
        public IEnumerable<FileDirectoryEntry> QueryDirectoryInfo()
        {
            return QueryDirectoryInfo(null, FileTypeMask.All);
        }

        /// <summary>
        /// Query a directory for files.
        /// </summary>
        /// <param name="file_mask">A file name mask (such as *.txt). Can be null.</param>
        /// <param name="type_mask">Indicate what entries to return.</param>
        /// <returns></returns>
        public IEnumerable<FileDirectoryEntry> QueryDirectoryInfo(string file_mask, FileTypeMask type_mask)
        {
            UnicodeString mask = new UnicodeString(string.IsNullOrEmpty(file_mask) ? "*" : file_mask);
            // 32k seems to be a reasonable size, too big and some volumes will fail with STATUS_INVALID_PARAMETER.
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(32 * 1024))
            {
                using (NtAsyncResult result = new NtAsyncResult(this))
                {
                    NtStatus status = result.CompleteCall(NtSystemCalls.NtQueryDirectoryFile(Handle, result.EventHandle,
                        IntPtr.Zero, IntPtr.Zero, result.IoStatusBuffer, buffer, buffer.Length,
                        FileInformationClass.FileDirectoryInformation, false, mask, true));

                    while (status.IsSuccess())
                    {
                        var dir_buffer = buffer.GetStructAtOffset<FileDirectoryInformation>(0);
                        do
                        {
                            FileDirectoryInformation dir_info = dir_buffer.Result;
                            bool valid_entry = false;
                            switch (type_mask)
                            {
                                case FileTypeMask.All:
                                    valid_entry = true;
                                    break;
                                case FileTypeMask.FilesOnly:
                                    valid_entry = (dir_info.FileAttributes & FileAttributes.Directory) == 0;
                                    break;
                                case FileTypeMask.DirectoriesOnly:
                                    valid_entry = (dir_info.FileAttributes & FileAttributes.Directory) == FileAttributes.Directory;
                                    break;
                            }

                            string file_name = dir_buffer.Data.ReadUnicodeString(dir_info.FileNameLength / 2);
                            if (file_name == "." || file_name == "..")
                            {
                                valid_entry = false;
                            }

                            if (valid_entry)
                            {
                                yield return new FileDirectoryEntry(dir_info, dir_buffer.Data.ReadUnicodeString(dir_info.FileNameLength / 2));
                            }

                            if (dir_info.NextEntryOffset == 0)
                            {
                                break;
                            }
                            dir_buffer = dir_buffer.GetStructAtOffset<FileDirectoryInformation>(dir_info.NextEntryOffset);
                        }
                        while (true);

                        result.Reset();
                        status = result.CompleteCall(NtSystemCalls.NtQueryDirectoryFile(Handle, result.EventHandle, IntPtr.Zero, IntPtr.Zero,
                            result.IoStatusBuffer, buffer, buffer.Length, FileInformationClass.FileDirectoryInformation, false, mask, false));
                    }

                    if (status != NtStatus.STATUS_NO_MORE_FILES && status != NtStatus.STATUS_NO_SUCH_FILE)
                    {
                        status.ToNtException();
                    }
                }
            }
        }

        /// <summary>
        /// Read data from a file with a length and position.
        /// </summary>
        /// <param name="buffer">The buffer to read to.</param>
        /// <param name="position">The position in the file to read. The position is optional.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The length of bytes read into the buffer.</returns>
        public NtResult<int> Read(SafeBuffer buffer, long? position, bool throw_on_error)
        {
            using (NtAsyncResult result = new NtAsyncResult(this))
            {
                return result.CompleteCall(NtSystemCalls.NtReadFile(Handle, result.EventHandle, IntPtr.Zero,
                    IntPtr.Zero, result.IoStatusBuffer, buffer, buffer.GetLength(), position.ToLargeInteger(), IntPtr.Zero))
                    .CreateResult(throw_on_error, () => result.Information32);
            }
        }

        /// <summary>
        /// Read data from a file with a length and position.
        /// </summary>
        /// <param name="buffer">The buffer to read to.</param>
        /// <param name="position">The position in the file to read. The position is optional.</param>
        /// <returns>The length of bytes read into the buffer.</returns>
        public int Read(SafeBuffer buffer, long? position)
        {
            return Read(buffer, position, true).Result;
        }

        /// <summary>
        /// Read data from a file with a length and position.
        /// </summary>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read. The position is optional.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The read bytes, this can be smaller than length.</returns>
        public NtResult<byte[]> Read(int length, long? position, bool throw_on_error)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(length))
            {
                return Read(buffer, position, throw_on_error).Map(len => buffer.ReadBytes(len));
            }
        }

        /// <summary>
        /// Read data from a file with a length and position.
        /// </summary>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read</param>
        /// <returns>The read bytes, this can be smaller than length.</returns>
        public byte[] Read(int length, long position)
        {
            return Read(length, position, true).Result;
        }

        /// <summary>
        /// Read data from a file with a length.
        /// </summary>
        /// <param name="length">The length of the read</param>
        /// <returns>The read bytes, this can be smaller than length.</returns>
        public byte[] Read(int length)
        {
            return Read(length, null, true).Result;
        }

        /// <summary>
        /// Read data from a file with a length and position asynchronously.
        /// </summary>
        /// <param name="buffer">The buffer to read to.</param>
        /// <param name="position">The position in the file to read. The position is optional.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The length of bytes read into the buffer.</returns>
        public async Task<NtResult<int>> ReadAsync(SafeBuffer buffer, long position, CancellationToken token, bool throw_on_error)
        {
            var status = await RunFileCallAsync(result => NtSystemCalls.NtReadFile(Handle, result.EventHandle, IntPtr.Zero,
                        IntPtr.Zero, result.IoStatusBuffer, buffer, buffer.GetLength(), new LargeInteger(position), IntPtr.Zero), token, throw_on_error);
            return status.Map(r => r.Information32);
        }

        /// <summary>
        /// Read data from a file with a length and position asynchronously.
        /// </summary>
        /// <param name="buffer">The buffer to read to.</param>
        /// <param name="position">The position in the file to read. The position is optional.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <returns>The length of bytes read into the buffer.</returns>
        public async Task<int> ReadAsync(SafeBuffer buffer, long position, CancellationToken token)
        {
            var result = await ReadAsync(buffer, position, token, true);
            return result.Result;
        }

        /// <summary>
        /// Read data from a file with a length and position asynchronously.
        /// </summary>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read. The position is optional.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The length of bytes read into the buffer.</returns>
        public async Task<NtResult<byte[]>> ReadAsync(int length, long position, CancellationToken token, bool throw_on_error)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(length))
            {
                var result = await ReadAsync(buffer, position, token, true);
                return result.Map(r => buffer.ReadBytes(r));
            }
        }

        /// <summary>
        /// Read data from a file with a length and position asynchronously..
        /// </summary>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <returns>The read bytes, this can be smaller than length.</returns>
        public async Task<byte[]> ReadAsync(int length, long position, CancellationToken token)
        {
            var result = await ReadAsync(length, position, token, true);
            return result.Result;
        }

        /// <summary>
        /// Read data from a file with a length and position asynchronously..
        /// </summary>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read</param>
        /// <returns>The read bytes, this can be smaller than length.</returns>
        public Task<byte[]> ReadAsync(int length, long position)
        {
            return ReadAsync(length, position, CancellationToken.None);
        }

        /// <summary>
        /// Write data to a file at a specific position asynchronously.
        /// </summary>
        /// <param name="data">The data to write as a buffer.</param>
        /// <param name="position">The position to write to.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The number of bytes written</returns>
        public async Task<NtResult<int>> WriteAsync(SafeBuffer data, long position, CancellationToken token, bool throw_on_error)
        {
            var result = await RunFileCallAsync(r => NtSystemCalls.NtWriteFile(Handle, r.EventHandle, IntPtr.Zero,
                        IntPtr.Zero, r.IoStatusBuffer, data, data.GetLength(), new LargeInteger(position), IntPtr.Zero), token,
                        throw_on_error);
            return result.Map(r => r.Information32);
        }

        /// <summary>
        /// Write data to a file at a specific position asynchronously.
        /// </summary>
        /// <param name="data">The data to write as a buffer.</param>
        /// <param name="position">The position to write to.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <returns>The number of bytes written</returns>
        public async Task<int> WriteAsync(SafeBuffer data, long position, CancellationToken token)
        {
            var result = await WriteAsync(data, position, token, true);
            return result.Result;
        }

        /// <summary>
        /// Write data to a file at a specific position.
        /// </summary>
        /// <param name="data">The data to write</param>
        /// <param name="position">The position to write to. Optional</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The number of bytes written.</returns>
        public NtResult<int> Write(SafeBuffer data, long? position, bool throw_on_error)
        {
            using (NtAsyncResult result = new NtAsyncResult(this))
            {
                return result.CompleteCall(NtSystemCalls.NtWriteFile(Handle, result.EventHandle, IntPtr.Zero,
                    IntPtr.Zero, result.IoStatusBuffer, data, data.GetLength(), position.ToLargeInteger(), IntPtr.Zero))
                    .CreateResult(throw_on_error, () => result.Information32);
            }
        }

        /// <summary>
        /// Write data to a file at a specific position.
        /// </summary>
        /// <param name="data">The data to write</param>
        /// <param name="position">The position to write to. Optional</param>
        /// <returns>The number of bytes written.</returns>
        public int Write(SafeBuffer data, long? position)
        {
            return Write(data, position, true).Result;
        }

        /// <summary>
        /// Write data to a file at a specific position.
        /// </summary>
        /// <param name="data">The data to write</param>
        /// <param name="position">The position to write to. Optional</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The number of bytes written.</returns>
        public NtResult<int> Write(byte[] data, long? position, bool throw_on_error)
        {
            using (var buffer = data.ToBuffer())
            {
                return Write(buffer, position, throw_on_error);
            }
        }

        /// <summary>
        /// Write data to a file at a specific position.
        /// </summary>
        /// <param name="data">The data to write</param>
        /// <param name="position">The position to write to</param>
        /// <returns>The number of bytes written</returns>
        public int Write(byte[] data, long position)
        {
            return Write(data, position, true).Result;
        }

        /// <summary>
        /// Write data to a file
        /// </summary>
        /// <param name="data">The data to write</param>
        /// <returns>The number of bytes written</returns>
        public int Write(byte[] data)
        {
            return Write(data, null, true).Result;
        }

        /// <summary>
        /// Write data to a file at a specific position asynchronously.
        /// </summary>
        /// <param name="data">The data to write</param>
        /// <param name="position">The position to write to</param>
        /// <returns>The number of bytes written</returns>
        public Task<int> WriteAsync(byte[] data, long position)
        {
            return WriteAsync(data, position, CancellationToken.None);
        }

        /// <summary>
        /// Write data to a file at a specific position asynchronously.
        /// </summary>
        /// <param name="data">The data to write.</param>
        /// <param name="position">The position to write to.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The number of bytes written</returns>
        public async Task<NtResult<int>> WriteAsync(byte[] data, long position, CancellationToken token, bool throw_on_error)
        {
            using (var buffer = data.ToBuffer())
            {
                return await WriteAsync(buffer, position, token, true);
            }
        }

        /// <summary>
        /// Write data to a file at a specific position asynchronously.
        /// </summary>
        /// <param name="data">The data to write.</param>
        /// <param name="position">The position to write to.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <returns>The number of bytes written</returns>
        public async Task<int> WriteAsync(byte[] data, long position, CancellationToken token)
        {
            var result = await WriteAsync(data, position, token, true);
            return result.Result;
        }

        /// <summary>
        /// Lock part of a file.
        /// </summary>
        /// <param name="offset">The offset into the file to lock</param>
        /// <param name="size">The number of bytes to lock</param>
        /// <param name="fail_immediately">True to fail immediately if the lock can't be taken</param>
        /// <param name="exclusive">True to do an exclusive lock</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Lock(long offset, long size, bool fail_immediately, bool exclusive, bool throw_on_error)
        {
            using (NtAsyncResult result = new NtAsyncResult(this))
            {
                return result.CompleteCall(NtSystemCalls.NtLockFile(Handle, result.EventHandle, IntPtr.Zero,
                    IntPtr.Zero, result.IoStatusBuffer, new LargeInteger(offset),
                    new LargeInteger(size), 0, fail_immediately, exclusive)).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Lock part of a file.
        /// </summary>
        /// <param name="offset">The offset into the file to lock</param>
        /// <param name="size">The number of bytes to lock</param>
        /// <param name="fail_immediately">True to fail immediately if the lock can't be taken</param>
        /// <param name="exclusive">True to do an exclusive lock</param>
        public void Lock(long offset, long size, bool fail_immediately, bool exclusive)
        {
            Lock(offset, size, fail_immediately, exclusive, true);
        }

        /// <summary>
        /// Shared lock part of a file.
        /// </summary>
        /// <param name="offset">The offset into the file to lock</param>
        /// <param name="size">The number of bytes to lock</param>
        public void Lock(long offset, long size)
        {
            Lock(offset, size, false, false);
        }

        /// <summary>
        /// Lock part of a file asynchronously.
        /// </summary>
        /// <param name="offset">The offset into the file to lock</param>
        /// <param name="size">The number of bytes to lock</param>
        /// <param name="fail_immediately">True to fail immediately if the lock can't be taken</param>
        /// <param name="exclusive">True to do an exclusive lock</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public async Task<NtStatus> LockAsync(long offset, long size, bool fail_immediately,
            bool exclusive, CancellationToken token, bool throw_on_error)
        {
            var result = await RunFileCallAsync(r => NtSystemCalls.NtLockFile(Handle, r.EventHandle, IntPtr.Zero,
                                                                     IntPtr.Zero, r.IoStatusBuffer, new LargeInteger(offset),
                                                                     new LargeInteger(size), 0, fail_immediately, exclusive),
                                                                     token, throw_on_error);
            return result.Status;
        }

        /// <summary>
        /// Lock part of a file asynchronously.
        /// </summary>
        /// <param name="offset">The offset into the file to lock</param>
        /// <param name="size">The number of bytes to lock</param>
        /// <param name="fail_immediately">True to fail immediately if the lock can't be taken</param>
        /// <param name="exclusive">True to do an exclusive lock</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        public async Task LockAsync(long offset, long size, bool fail_immediately, bool exclusive, CancellationToken token)
        {
            await LockAsync(offset, size, fail_immediately, exclusive, token, true);
        }

        /// <summary>
        /// Lock part of a file asynchronously.
        /// </summary>
        /// <param name="offset">The offset into the file to lock</param>
        /// <param name="size">The number of bytes to lock</param>
        /// <param name="fail_immediately">True to fail immediately if the lock can't be taken</param>
        /// <param name="exclusive">True to do an exclusive lock</param>
        public Task LockAsync(long offset, long size, bool fail_immediately, bool exclusive)
        {
            return LockAsync(offset, size, fail_immediately, exclusive, CancellationToken.None);
        }

        /// <summary>
        /// Shared lock part of a file asynchronously.
        /// </summary>
        /// <param name="offset">The offset into the file to lock</param>
        /// <param name="size">The number of bytes to lock</param>
        public Task LockAsync(long offset, long size)
        {
            return LockAsync(offset, size, false, false);
        }

        /// <summary>
        /// Unlock part of a file previously locked with Lock
        /// </summary>
        /// <param name="offset">The offset into the file to unlock</param>
        /// <param name="size">The number of bytes to unlock</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Unlock(long offset, long size)
        {
            Unlock(offset, size, true);
        }

        /// <summary>
        /// Unlock part of a file previously locked with Lock
        /// </summary>
        /// <param name="offset">The offset into the file to unlock</param>
        /// <param name="size">The number of bytes to unlock</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Unlock(long offset, long size, bool throw_on_error)
        {
            IoStatus io_status = new IoStatus();
            return NtSystemCalls.NtUnlockFile(Handle, io_status,
                new LargeInteger(offset), new LargeInteger(size), 0).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Convert this NtFile to a FileStream for reading/writing.
        /// </summary>
        /// <remarks>The stream must be closed separately from the NtFile.</remarks>
        /// <returns>The file stream.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public FileStream ToStream()
        {
            FileAccess access = FileAccess.Read;

            if (NtType.HasWritePermission(GrantedAccessMask))
            {
                access = FileAccess.ReadWrite;
            }
            return new FileStream(DuplicateAsFile(Handle), access);
        }

        /// <summary>
        /// Get the Win32 path name for the file.
        /// </summary>
        /// <param name="flags">The flags to determine what path information to get.</param>
        /// <returns>The path.</returns>
        /// <exception cref="NtException">Throw on error.</exception>
        public string GetWin32PathName(Win32PathNameFlags flags)
        {
            return GetWin32PathName(flags, true).Result;
        }

        /// <summary>
        /// Get the Win32 path name for the file.
        /// </summary>
        /// <param name="flags">The flags to determine what path information to get.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The path.</returns>
        public NtResult<string> GetWin32PathName(Win32PathNameFlags flags, bool throw_on_error)
        {
            return Win32Utils.GetWin32PathName(this, flags, true);
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="level">The level of oplock to set.</param>
        public void RequestOplock(OplockRequestLevel level)
        {
            FsControl(GetOplockFsctl(level), null, null);
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="level">The level of oplock to set.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        public Task<NtStatus> RequestOplockAsync(OplockRequestLevel level, CancellationToken token, bool throw_on_error)
        {
            return FsControlAsync(GetOplockFsctl(level), null, null, token, throw_on_error).UnwrapNtStatusAsync();
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="level">The level of oplock to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        public Task<NtStatus> RequestOplockAsync(OplockRequestLevel level, bool throw_on_error)
        {
            return RequestOplockAsync(level, CancellationToken.None, true);
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="level">The level of oplock to set.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        public Task RequestOplockAsync(OplockRequestLevel level, CancellationToken token)
        {
            return RequestOplockAsync(level, token, true);
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="level">The level of oplock to set.</param>
        public Task RequestOplockAsync(OplockRequestLevel level)
        {
            return RequestOplockAsync(level, CancellationToken.None);
        }

        /// <summary>
        /// Oplock the file with a specific level and flags.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock level.</param>
        /// <param name="flags">The flags for the oplock.</param>
        /// <returns>The request of the oplock request.</returns>
        public RequestOplockOutputBuffer RequestOplock(OplockLevelCache requested_oplock_level, RequestOplockInputFlag flags)
        {
            using (var input_buffer = new RequestOplockInputBuffer(requested_oplock_level, flags).ToBuffer())
            {
                using (var output_buffer = new SafeStructureInOutBuffer<RequestOplockOutputBuffer>())
                {
                    int size = FsControl(NtWellKnownIoControlCodes.FSCTL_REQUEST_OPLOCK, input_buffer, output_buffer);
                    if (size != output_buffer.Length)
                    {
                        throw new NtException(NtStatus.STATUS_BUFFER_TOO_SMALL);
                    }
                    return output_buffer.Result;
                }
            }
        }

        /// <summary>
        /// Oplock the file with a specific level and flags.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock level.</param>
        /// <param name="flags">The flags for the oplock.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <returns>The request of the oplock request.</returns>
        public async Task<RequestOplockOutputBuffer> RequestOplockAsync(OplockLevelCache requested_oplock_level, RequestOplockInputFlag flags, CancellationToken token)
        {
            using (var input_buffer = new RequestOplockInputBuffer(requested_oplock_level, flags).ToBuffer())
            {
                using (var output_buffer = new SafeStructureInOutBuffer<RequestOplockOutputBuffer>())
                {
                    int size = await FsControlAsync(NtWellKnownIoControlCodes.FSCTL_REQUEST_OPLOCK, input_buffer, output_buffer, token);
                    if (size != output_buffer.Length)
                    {
                        throw new NtException(NtStatus.STATUS_BUFFER_TOO_SMALL);
                    }
                    return output_buffer.Result;
                }
            }
        }

        /// <summary>
        /// Oplock the file with a specific level and flags.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock level.</param>
        /// <param name="flags">The flags for the oplock.</param>
        /// <returns>The request of the oplock request.</returns>
        public Task<RequestOplockOutputBuffer> RequestOplockAsync(OplockLevelCache requested_oplock_level, RequestOplockInputFlag flags)
        {
            return RequestOplockAsync(requested_oplock_level, flags, CancellationToken.None);
        }

        /// <summary>
        /// Oplock the file exclusively (no other users can access the file).
        /// </summary>
        public void OplockExclusive()
        {
            RequestOplock(OplockRequestLevel.Level1);
        }

        /// <summary>
        /// Oplock the file exclusively (no other users can access the file).
        /// </summary>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        public Task OplockExclusiveAsync(CancellationToken token)
        {
            return RequestOplockAsync(OplockRequestLevel.Level1, token);
        }

        /// <summary>
        /// Oplock the file exclusively (no other users can access the file).
        /// </summary>
        public Task OplockExclusiveAsync()
        {
            return OplockExclusiveAsync(CancellationToken.None);
        }

        /// <summary>
        /// Dispose.
        /// </summary>
        /// <param name="disposing">True is disposing.</param>
        protected override void Dispose(bool disposing)
        {
            // Cancel any potential ongoing IO calls.
            try
            {
                using (_cts)
                {
                    _cts.Cancel();
                }
            }
            catch
            {
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Try and cancel any pending asynchronous IO.
        /// </summary>
        public void CancelIo()
        {
            // Cancel token source then recreate a new one.
            using (_cts)
            {
                _cts.Cancel();
            }
            _cts = new CancellationTokenSource();
        }

        /// <summary>
        /// Get the extended attributes of a file.
        /// </summary>
        /// <returns>The extended attributes, empty if no extended attributes.</returns>
        public EaBuffer GetEa()
        {
            int ea_size = 1024;
            while (true)
            {
                IoStatus io_status = new IoStatus();
                byte[] buffer = new byte[ea_size];
                NtStatus status = NtSystemCalls.NtQueryEaFile(Handle, io_status, buffer, buffer.Length, false, SafeHGlobalBuffer.Null, 0, null, true);
                if (status == NtStatus.STATUS_BUFFER_OVERFLOW || status == NtStatus.STATUS_BUFFER_TOO_SMALL)
                {
                    ea_size *= 2;
                    continue;
                }
                else if (status.IsSuccess())
                {
                    return new EaBuffer(buffer);
                }
                else if (status == NtStatus.STATUS_NO_EAS_ON_FILE)
                {
                    return new EaBuffer();
                }
                else
                {
                    throw new NtException(status);
                }
            }
        }

        /// <summary>
        /// Set the extended attributes for a file.
        /// </summary>
        /// <param name="ea">The EA buffer to set.</param>
        /// <remarks>This will add entries if they no longer exist, 
        /// remove entries if the data is empty or update existing entires.</remarks>
        public void SetEa(EaBuffer ea)
        {
            byte[] ea_buffer = ea.ToByteArray();
            IoStatus io_status = new IoStatus();
            NtSystemCalls.NtSetEaFile(Handle, io_status, ea_buffer, ea_buffer.Length).ToNtException();
        }

        /// <summary>
        /// Set the extended attributes for a file.
        /// </summary>
        /// <param name="name">The name of the entry</param>
        /// <param name="data">The associated data</param>
        /// <param name="flags">The entry flags.</param>
        public void SetEa(string name, byte[] data, EaBufferEntryFlags flags)
        {
            EaBuffer ea = new EaBuffer();
            ea.AddEntry(name, data, flags);
            SetEa(ea);
        }

        /// <summary>
        /// Set the extended attributes for a file.
        /// </summary>
        /// <param name="name">The name of the entry</param>
        /// <param name="data">The associated data</param>
        /// <param name="flags">The entry flags.</param>
        public void AddEntry(string name, int data, EaBufferEntryFlags flags)
        {
            SetEa(name, BitConverter.GetBytes(data), flags);
        }

        /// <summary>
        /// Set the extended attributes for a file.
        /// </summary>
        /// <param name="name">The name of the entry</param>
        /// <param name="data">The associated data</param>
        /// <param name="flags">The entry flags.</param>
        public void SetEa(string name, string data, EaBufferEntryFlags flags)
        {
            SetEa(name, Encoding.Unicode.GetBytes(data), flags);
        }

        /// <summary>
        /// Remove an extended attributes entry for a file.
        /// </summary>
        /// <param name="name">The name of the entry</param>
        public void RemoveEa(string name)
        {
            EaBuffer ea = new EaBuffer();
            ea.AddEntry(name, new byte[0], EaBufferEntryFlags.None);
            SetEa(ea);
        }

        /// <summary>
        /// Assign completion port to file.
        /// </summary>
        /// <param name="completion_port">The completion port.</param>
        /// <param name="key">A key to associate with this completion.</param>
        public void SetCompletionPort(NtIoCompletion completion_port, IntPtr key)
        {
            FileCompletionInformation info = new FileCompletionInformation();
            info.CompletionPort = completion_port.Handle.DangerousGetHandle();
            info.Key = key;

            Set(FileInformationClass.FileCompletionInformation, info);
        }

        /// <summary>
        /// Check if a specific set of file directory access rights is granted
        /// </summary>
        /// <param name="access">The file directory access rights to check</param>
        /// <returns>True if all access rights are granted</returns>
        public bool IsAccessGranted(FileDirectoryAccessRights access)
        {
            return IsAccessMaskGranted(access);
        }

        /// <summary>
        /// Get the cached signing level for a file.
        /// </summary>
        /// <returns>The cached signing level.</returns>
        public CachedSigningLevel GetCachedSigningLevel()
        {
            return NtSecurity.GetCachedSigningLevel(Handle);
        }

        /// <summary>
        /// Get the cached singing level from the raw EA buffer.
        /// </summary>
        /// <returns>The cached signing level data.</returns>
        /// <exception cref="NtException">Throw on error.</exception>
        public CachedSigningLevel GetCachedSigningLevelFromEa()
        {
            return NtSecurity.GetCachedSigningLevelFromEa(GetEa());
        }

        /// <summary>
        /// Set the cached signing level for a file.
        /// </summary>
        /// <param name="flags">Flags to set for the cache.</param>
        /// <param name="signing_level">The signing level to cache</param>
        public void SetCachedSigningLevel(int flags, SigningLevel signing_level)
        {
            SetCachedSigningLevel(flags, signing_level, null);
        }

        /// <summary>
        /// Set the cached signing level for a file.
        /// </summary>
        /// <param name="flags">Flags to set for the cache.</param>
        /// <param name="signing_level">The signing level to cache</param>
        /// <param name="catalog_path">Optional directory path to look for catalog files.</param>
        public void SetCachedSigningLevel(int flags, SigningLevel signing_level, string catalog_path)
        {
            SetCachedSigningLevel(flags, signing_level, new NtFile[] { this }, catalog_path);
        }

        /// <summary>
        /// Set the cached signing level for a file.
        /// </summary>
        /// <param name="flags">Flags to set for the cache.</param>
        /// <param name="signing_level">The signing level to cache</param>
        /// <param name="files">Files for signature.</param>
        /// <param name="catalog_path">Optional directory path to look for catalog files.</param>
        public void SetCachedSigningLevel(int flags, SigningLevel signing_level, IEnumerable<NtFile> files, string catalog_path)
        {
            NtSecurity.SetCachedSigningLevel(Handle, flags, signing_level, files.Select(f => f.Handle), catalog_path);
        }

        /// <summary>
        /// Set the end of file.
        /// </summary>
        /// <param name="offset">The offset to the end of file.</param>
        public void SetEndOfFile(long offset)
        {
            FileEndOfFileInformation eof = new FileEndOfFileInformation();
            eof.EndOfFile.QuadPart = offset;
            Set(FileInformationClass.FileEndOfFileInformation, eof);
        }

        /// <summary>
        /// Set the valid data length of the file without zeroing. Needs SeManageVolumePrivilege.
        /// </summary>
        /// <param name="length">The length to set.</param>
        public void SetValidDataLength(long length)
        {
            FileValidDataLengthInformation data_length = new FileValidDataLengthInformation();
            data_length.ValidDataLength.QuadPart = length;
            Set(FileInformationClass.FileValidDataLengthInformation, data_length);
        }

        /// <summary>
        /// Get list of hard link entries for a file.
        /// </summary>
        /// <returns>The list of entries.</returns>
        public IEnumerable<FileLinkEntry> GetHardLinks()
        {
            int size = 16 * 1024;
            while (true)
            {
                FileLinksInformation info = new FileLinksInformation();
                info.BytesNeeded = size;

                using (var buffer = new SafeStructureInOutBuffer<FileLinksInformation>(info, size, true))
                {
                    IoStatus io_status = new IoStatus();
                    NtStatus status = NtSystemCalls.NtQueryInformationFile(Handle, io_status,
                        buffer, buffer.Length, FileInformationClass.FileHardLinkInformation);
                    if (status == NtStatus.STATUS_BUFFER_OVERFLOW)
                    {
                        size *= 2;
                        continue;
                    }
                    status.ToNtException();
                    info = buffer.Result;

                    int ofs = 0;

                    for (int i = 0; i < info.EntriesReturned; ++i)
                    {
                        var entry_buffer = buffer.Data.GetStructAtOffset<FileLinkEntryInformation>(ofs);
                        var entry = entry_buffer.Result;
                        string parent_path = String.Empty;

                        using (var parent = OpenFileById(this, NtFileUtils.FileIdToString(entry.ParentFileId),
                            FileAccessRights.ReadAttributes, FileShareMode.None, FileOpenOptions.None, false))
                        {
                            if (parent.IsSuccess)
                            {
                                parent_path = parent.Result.FullPath;
                            }
                        }

                        yield return new FileLinkEntry(entry_buffer, parent_path);

                        if (entry.NextEntryOffset == 0)
                        {
                            break;
                        }
                        ofs = ofs + entry.NextEntryOffset;
                    }
                    break;
                }
            }
        }

        /// <summary>
        /// Get a list of stream entries for the current file.
        /// </summary>
        /// <returns>The list of streams.</returns>
        public IEnumerable<FileStreamEntry> GetStreams()
        {
            bool done = false;
            int size = 16 * 1024;
            while (!done)
            {
                using (var buffer = new SafeHGlobalBuffer(size))
                {
                    IoStatus io_status = new IoStatus();
                    NtStatus status = NtSystemCalls.NtQueryInformationFile(Handle, io_status,
                        buffer, buffer.Length, FileInformationClass.FileStreamInformation);
                    if (status == NtStatus.STATUS_BUFFER_OVERFLOW)
                    {
                        size *= 2;
                        continue;
                    }
                    status.ToNtException();
                    done = true;

                    int ofs = 0;
                    while (ofs < io_status.Information32)
                    {
                        var stream = buffer.GetStructAtOffset<FileStreamInformation>(ofs);
                        var result = stream.Result;
                        yield return new FileStreamEntry(stream);
                        if (result.NextEntryOffset == 0)
                        {
                            break;
                        }
                        ofs += result.NextEntryOffset;
                    }
                }
            }
        }

        /// <summary>
        /// Visit all accessible streams under this file.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible stream. Return true to continue enumeration.</param>
        /// <param name="desired_access">Specify the desired access for the streams.</param>
        /// <param name="share_access">The share access to open the streams with.</param>
        /// <param name="open_options">Additional options to open the s with.</param>
        /// <returns>True if all accessible streams were visited, false if not.</returns>
        public bool VisitAccessibleStreams(Func<NtFile, bool> visitor, FileAccessRights desired_access,
            FileShareMode share_access, FileOpenOptions open_options)
        {
            foreach (var stream in GetStreams().Where(s => !s.Name.Equals("::$DATA")))
            {
                if (!VisitFileEntry(stream.Name, false, visitor, desired_access, share_access, open_options))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Get list of process ids using this file.
        /// </summary>
        /// <returns>The list of process ids.</returns>
        public IEnumerable<int> GetUsingProcessIds()
        {
            using (var buffer = new SafeStructureInOutBuffer<FileProcessIdsUsingFileInformation>(8 * 1024, true))
            {
                IoStatus io_status = new IoStatus();
                NtSystemCalls.NtQueryInformationFile(Handle, io_status,
                    buffer, buffer.Length, FileInformationClass.FileProcessIdsUsingFileInformation).ToNtException();
                var result = buffer.Result;
                IntPtr[] pids = new IntPtr[result.NumberOfProcessIdsInList];
                buffer.Data.ReadArray(0, pids, 0, result.NumberOfProcessIdsInList);
                return pids.Select(p => p.ToInt32());
            }
        }

        /// <summary>
        /// Visit all accessible files under this directory.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible file. Return true to continue enumeration.</param>
        /// <param name="desired_access">Specify the desired access for the files.</param>
        /// <param name="recurse">True to recurse into sub keys.</param>
        /// <param name="share_access">The share access to open the files with.</param>
        /// <param name="max_depth">Specify max recursive depth. -1 to not set a limit.</param>
        /// <param name="open_options">Additional options to open the files with.</param>
        /// <param name="file_mask">A file name mask (such as *.txt). Can be null.</param>
        /// <param name="type_mask">Indicate what entries to return.</param>
        /// <returns>True if all accessible files were visited, false if not.</returns>
        public bool VisitAccessibleFiles(Func<NtFile, bool> visitor, FileAccessRights desired_access,
            FileShareMode share_access, FileOpenOptions open_options, bool recurse, int max_depth,
            string file_mask, FileTypeMask type_mask)
        {
            if (max_depth == 0)
            {
                return true;
            }

            foreach (var entry in QueryDirectoryInfo(file_mask, type_mask))
            {
                if (!VisitFileEntry(entry.FileName, entry.IsDirectory, visitor, desired_access, share_access, open_options))
                {
                    return false;
                }
            }

            if (!recurse)
            {
                return true;
            }

            if (max_depth > 0)
            {
                max_depth--;
            }

            foreach (var entry in QueryDirectoryInfo(null, FileTypeMask.DirectoriesOnly))
            {
                if (!VisitFileEntry(entry.FileName, entry.IsDirectory,
                    f => f.VisitAccessibleFiles(visitor, desired_access, share_access, open_options, recurse, max_depth, file_mask, type_mask),
                        FileDirectoryAccessRights.ListDirectory.ToFileAccessRights(), FileShareMode.Read | FileShareMode.Delete,
                    (open_options & FileOpenOptions.OpenForBackupIntent) | FileOpenOptions.OpenReparsePoint))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Visit all accessible files under this directory.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible file. Return true to continue enumeration.</param>
        /// <param name="desired_access">Specify the desired access for the files.</param>
        /// <param name="recurse">True to recurse into sub keys.</param>
        /// <param name="share_access">The share access to open the files with.</param>
        /// <param name="max_depth">Specify max recursive depth. -1 to not set a limit.</param>
        /// <param name="open_options">Additional options to open the files with.</param>
        /// <returns>True if all accessible files were visited, false if not.</returns>
        public bool VisitAccessibleFiles(Func<NtFile, bool> visitor, FileAccessRights desired_access,
            FileShareMode share_access, FileOpenOptions open_options, bool recurse, int max_depth)
        {
            return VisitAccessibleFiles(visitor, desired_access, share_access, open_options, recurse, max_depth, null, FileTypeMask.All);
        }

        /// <summary>
        /// Visit all accessible files under this directory.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible file. Return true to continue enumeration.</param>
        public void VisitAccessibleFiles(Func<NtFile, bool> visitor)
        {
            VisitAccessibleFiles(visitor, FileAccessRights.MaximumAllowed, FileShareMode.Read | FileShareMode.Delete);
        }

        /// <summary>
        /// Visit all accessible files under this directory.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible file. Return true to continue enumeration.</param>
        /// <param name="desired_access">Specify the desired access for the files.</param>
        /// <param name="share_access">The share access to open the files with.</param>
        public void VisitAccessibleFiles(Func<NtFile, bool> visitor, FileAccessRights desired_access,
            FileShareMode share_access)
        {
            VisitAccessibleFiles(visitor, desired_access, share_access, FileOpenOptions.None, false, -1, null, FileTypeMask.All);
        }

        /// <summary>
        /// Query whether a file is trusted for dynamic code.
        /// </summary>
        /// <returns>Returns true if the file is trusted.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS4)]
        public bool QueryDynamicCodeTrust()
        {
            return NtSystemInfo.QueryDynamicCodeTrust(Handle).IsSuccess();
        }

        /// <summary>
        /// Set a file is trusted for dynamic code.
        /// </summary>
        [SupportedVersion(SupportedVersion.Windows10_RS4)]
        public void SetDynamicCodeTrust()
        {
            NtSystemInfo.SetDynamicCodeTrust(Handle).ToNtException();
        }

        /// <summary>
        /// Find files in a directory by the owner SID.
        /// </summary>
        /// <param name="sid">The owner SID.</param>
        /// <returns>A list of files in the directory.</returns>
        /// <remarks>For this method to work you need Quota enabled on the volume.</remarks>
        public IEnumerable<string> FindFilesBySid(Sid sid)
        {
            FindBySidData input = new FindBySidData
            {
                Restart = 1
            };
            byte[] sid_buffer = sid.ToArray();

            using (var buffer = input.ToBuffer(sid_buffer.Length, true))
            {
                buffer.Data.WriteBytes(sid_buffer);
                using (var out_buffer = new SafeHGlobalBuffer(4096))
                {
                    while (true)
                    {
                        var return_length = FsControl(NtWellKnownIoControlCodes.FSCTL_FIND_FILES_BY_SID, buffer, out_buffer, false);
                        if (return_length.Status == NtStatus.STATUS_NO_QUOTAS_FOR_ACCOUNT)
                        {
                            throw new NtException(NtStatus.STATUS_NO_QUOTAS_FOR_ACCOUNT);
                        }

                        int length = return_length.GetResultOrThrow();
                        if (length == 0)
                        {
                            yield break;
                        }

                        // First entry seems to be empty, but process anyway.
                        int ofs = 0;

                        while (ofs < length)
                        {
                            var res_buffer = out_buffer.GetStructAtOffset<FileNameInformation>(ofs);
                            var result = res_buffer.Result;
                            if (result.NameLength > 0)
                            {
                                yield return res_buffer.Data.ReadUnicodeString(result.NameLength / 2);
                            }

                            int total_length = (4 + result.NameLength + 8) & ~7;
                            ofs += total_length;
                        }
                        // Modify restart to 0.
                        buffer.Write(0, 0);
                    }
                }
            }
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(FileInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            IoStatus io_status = new IoStatus();
            NtStatus status = NtSystemCalls.NtQueryInformationFile(Handle, io_status, buffer, buffer.GetLength(), info_class);
            return_length = io_status.Information32;
            return status;
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public override NtStatus SetInformation(FileInformationClass info_class, SafeBuffer buffer)
        {
            IoStatus io_status = new IoStatus();
            return NtSystemCalls.NtSetInformationFile(Handle, io_status, buffer, buffer.GetLength(), info_class);
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Get object ID for current file
        /// </summary>
        /// <returns>The object ID as a string</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public string FileId
        {
            get
            {
                var internal_info = Query<FileInternalInformation>(FileInformationClass.FileInternalInformation);
                return NtFileUtils.FileIdToString(internal_info.IndexNumber.QuadPart);
            }
        }

        /// <summary>
        /// Get or set the attributes of a file.
        /// </summary>
        /// <returns>The file attributes</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public FileAttributes FileAttributes
        {
            get
            {
                return Query<FileBasicInformation>(FileInformationClass.FileBasicInformation).FileAttributes;
            }
            set
            {
                var basic_info = new FileBasicInformation() { FileAttributes = value };
                Set(FileInformationClass.FileBasicInformation, basic_info);
            }
        }

        /// <summary>
        /// Get whether this file represents a directory.
        /// </summary>
        public bool IsDirectory
        {
            get
            {
                if (!_is_directory.HasValue)
                {
                    _is_directory = (FileAttributes & FileAttributes.Directory) == FileAttributes.Directory;
                }
                return _is_directory.Value;
            }
        }

        /// <summary>
        /// Get whether this file repsents a reparse point.
        /// </summary>
        public bool IsReparsePoint
        {
            get
            {
                return (FileAttributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint;
            }
        }

        /// <summary>
        /// The result of opening the file, whether it was created, overwritten etc.
        /// </summary>
        public FileOpenResult OpenResult { get; }

        /// <summary>
        /// Get or set the current file position.
        /// </summary>
        public long Position
        {
            get
            {
                return Query<FilePositionInformation>(FileInformationClass.FilePositionInformation).CurrentByteOffset.QuadPart;
            }

            set
            {
                var position = new FilePositionInformation();
                position.CurrentByteOffset.QuadPart = value;

                Set(FileInformationClass.FilePositionInformation, position);
            }
        }

        /// <summary>
        /// Get or sets the file's length
        /// </summary>
        public long Length
        {
            get
            {
                return Query<FileStandardInformation>(FileInformationClass.FileStandardInformation).EndOfFile.QuadPart;
            }

            set
            {
                SetEndOfFile(value);
            }
        }

        /// <summary>
        /// Get the Win32 path name for the file.
        /// </summary>
        /// <returns>The path, String.Empty on error.</returns>
        public string Win32PathName
        {
            get
            {
                var result = GetWin32PathName(Win32.Win32PathNameFlags.None, false);
                if (!result.IsSuccess)
                {
                    return string.Empty;
                }

                var ret = result.Result;

                if (ret.StartsWith(@"\\?\"))
                {
                    if (ret.StartsWith(@"\\?\GLOBALROOT\", StringComparison.OrdinalIgnoreCase))
                    {
                        return ret;
                    }
                    else if (ret.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                    {
                        return @"\\" + ret.Substring(8);
                    }
                    else
                    {
                        return ret.Substring(4);
                    }
                }
                return ret;
            }
        }

        /// <summary>
        /// Get the low-level device type of the file.
        /// </summary>
        /// <returns>The file device type.</returns>
        public FileDeviceType DeviceType
        {
            get
            {
                return QueryVolumeFixed<FileFsDeviceInformation>(FsInformationClass.FileFsDeviceInformation).DeviceType;
            }
        }

        /// <summary>
        /// Get the low-level device characteristics of the file.
        /// </summary>
        /// <returns>The file device characteristics.</returns>
        public FileDeviceCharacteristics Characteristics
        {
            get
            {
                return QueryVolumeFixed<FileFsDeviceInformation>(FsInformationClass.FileFsDeviceInformation).Characteristics;
            }
        }

        /// <summary>
        /// Get filesystem and volume information.
        /// </summary>
        public FileSystemVolumeInformation VolumeInformation
        {
            get
            {
                using (var attr_info = QueryVolume<FileFsAttributeInformation>(FsInformationClass.FileFsAttributeInformation))
                {
                    using (var vol_info = QueryVolume<FileFsVolumeInformation>(FsInformationClass.FileFsVolumeInformation))
                    {
                        return new FileSystemVolumeInformation(attr_info, vol_info);
                    }
                }
            }
        }

        /// <summary>
        /// Get or set the file's compression format.
        /// </summary>
        public CompressionFormat CompressionFormat
        {
            get
            {
                using (var buffer = new SafeStructureInOutBuffer<int>())
                {
                    FsControl(NtWellKnownIoControlCodes.FSCTL_GET_COMPRESSION, SafeHGlobalBuffer.Null, buffer);
                    return (CompressionFormat)buffer.Result;
                }
            }
            set
            {
                using (var buffer = ((int)value).ToBuffer())
                {
                    FsControl(NtWellKnownIoControlCodes.FSCTL_SET_COMPRESSION, buffer, SafeHGlobalBuffer.Null);
                }
            }
        }


        /// <summary>
        /// Gets whether the file is on a remote file system.
        /// </summary>
        public bool IsRemote
        {
            get
            {
                return Query<bool>(FileInformationClass.FileIsRemoteDeviceInformation);
            }
        }

        /// <summary>
        /// Get or set whether this file/directory is case sensitive.
        /// </summary>
        public bool CaseSensitive
        {
            get
            {
                var result = Query(FileInformationClass.FileCaseSensitiveInformation, 0, false);
                if (!result.IsSuccess)
                {
                    return false;
                }

                return (result.Result & 1) == 1;
            }

            set
            {
                Set(FileInformationClass.FileCaseSensitiveInformation, value ? 1 : 0);
            }
        }


        /// <summary>
        /// Get the file mode.
        /// </summary>
        public FileOpenOptions Mode
        {
            get
            {
                return (FileOpenOptions)Query<int>(FileInformationClass.FileModeInformation);
            }
        }

        /// <summary>
        /// Get file access information.
        /// </summary>
        public AccessMask Access
        {
            get
            {
                return Query<AccessMask>(FileInformationClass.FileAccessInformation);
            }
        }

        /// <summary>
        /// Get the filename with the volume path.
        /// </summary>
        public string FileName
        {
            get
            {
                return TryGetName(FileInformationClass.FileNameInformation);
            }
        }

        /// <summary>
        /// Get the associated short filename
        /// </summary>
        public string FileShortName
        {
            get
            {
                return TryGetName(FileInformationClass.FileAlternateNameInformation);
            }
            set
            {
                SetName(FileInformationClass.FileShortNameInformation, value);
            }
        }

        /// <summary>
        /// Get the name of the file.
        /// </summary>
        /// <returns>The name of the file.</returns>
        public override string FullPath
        {
            get
            {
                if (DeviceType != FileDeviceType.NAMED_PIPE)
                {
                    return base.FullPath;
                }
                else
                {
                    return base.FullPath;
                }
            }
        }

        #endregion
    }
}
