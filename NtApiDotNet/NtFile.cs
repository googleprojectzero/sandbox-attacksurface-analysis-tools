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
using System;
using System.Collections.Generic;
using System.ComponentModel;
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
        Achive = 0x00000020,
        Device = 0x00000040,
        Normal = 0x00000080,
        Temporary = 0x00000100,
        SparseFile = 0x00000200,
        RepasePoint = 0x00000400,
        Compressed = 0x00000800,
        Offline = 0x00001000,
        NotContentIndexed = 0x00002000,
        Encrypted = 0x00004000,
        IntegrityStream = 0x00008000,
        Virtual = 0x00010000,
        NoScrubData = 0x00020000,
        Ea = 0x00040000,
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
        PORT_8042 = 0x00000027,
        ACPI = 0x00000032,
        BATTERY = 0x00000029,
        BEEP = 0x00000001,
        BUS_EXTENDER = 0x0000002a,
        CD_ROM = 0x00000002,
        CD_ROM_FILE_SYSTEM = 0x00000003,
        CHANGER = 0x00000030,
        CONTROLLER = 0x00000004,
        DATALINK = 0x00000005,
        DFS = 0x00000006,
        DFS_FILE_SYSTEM = 0x00000035,
        DFS_VOLUME = 0x00000036,
        DISK = 0x00000007,
        DISK_FILE_SYSTEM = 0x00000008,
        DVD = 0x00000033,
        FILE_SYSTEM = 0x00000009,
        FIPS = 0x0000003a,
        FULLSCREEN_VIDEO = 0x00000034,
        INPORT_PORT = 0x0000000a,
        KEYBOARD = 0x0000000b,
        KS = 0x0000002f,
        KSEC = 0x00000039,
        MAILSLOT = 0x0000000c,
        MASS_STORAGE = 0x0000002d,
        MIDI_IN = 0x0000000d,
        MIDI_OUT = 0x0000000e,
        MODEM = 0x0000002b,
        MOUSE = 0x0000000f,
        MULTI_UNC_PROVIDER = 0x00000010,
        NAMED_PIPE = 0x00000011,
        NETWORK = 0x00000012,
        NETWORK_BROWSER = 0x00000013,
        NETWORK_FILE_SYSTEM = 0x00000014,
        NETWORK_REDIRECTOR = 0x00000028,
        NULL = 0x00000015,
        PARALLEL_PORT = 0x00000016,
        PHYSICAL_NETCARD = 0x00000017,
        PRINTER = 0x00000018,
        SCANNER = 0x00000019,
        SCREEN = 0x0000001c,
        SERENUM = 0x00000037,
        SERIAL_MOUSE_PORT = 0x0000001a,
        SERIAL_PORT = 0x0000001b,
        SMARTCARD = 0x00000031,
        SMB = 0x0000002e,
        SOUND = 0x0000001d,
        STREAMS = 0x0000001e,
        TAPE = 0x0000001f,
        TAPE_FILE_SYSTEM = 0x00000020,
        TERMSRV = 0x00000038,
        TRANSPORT = 0x00000021,
        UNKNOWN = 0x00000022,
        VDM = 0x0000002c,
        VIDEO = 0x00000023,
        VIRTUAL_DISK = 0x00000024,
        WAVE_IN = 0x00000025,
        WAVE_OUT = 0x00000026,
    }

    [StructLayout(LayoutKind.Sequential)]
    public class FileFsDeviceInformation
    {
        public FileDeviceType DeviceType;
        public uint Characteristics;
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
    public class FileNameInformation
    {
        public int NameLength;
        [MarshalAs(UnmanagedType.ByValArray)]
        public char[] Name;

        public FileNameInformation()
        {
            Name = new char[1];
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public class FileBasicInformation
    {
        public LargeIntegerStruct CreationTime;
        public LargeIntegerStruct LastAccessTime;
        public LargeIntegerStruct LastWriteTime;
        public LargeIntegerStruct ChangeTime;
        public FileAttributes FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class FileEndOfFileInformation
    {
        public LargeIntegerStruct EndOfFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class FileValidDataLengthInformation
    {
        public LargeIntegerStruct ValidDataLength;
    }

    public enum FileControlMethod
    {
        Buffered = 0,
        InDirect = 1,
        OutDirect = 2,
        Neither = 3
    }

    [Flags]
    public enum FileControlAccess
    {
        Any = 0,
        Read = 1,
        Write = 2,
    }

    /// <summary>
    /// Represents a NT file IO control code.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct NtIoControlCode
    {
        private int _control_code;

        /// <summary>
        /// Type of device
        /// </summary>
        public FileDeviceType DeviceType
        {
            get
            {
                return (FileDeviceType)(_control_code >> 16);
            }
        }
        /// <summary>
        /// Function number
        /// </summary>
        public int Function
        {
            get
            {
                return (_control_code >> 2) & 0xFFF;
            }
        }

        /// <summary>
        /// Buffering method
        /// </summary>
        public FileControlMethod Method
        {
            get
            {
                return (FileControlMethod)(_control_code & 3);
            }
        }

        /// <summary>
        /// Access of file handle
        /// </summary>
        public FileControlAccess Access
        {
            get
            {
                return (FileControlAccess)((_control_code >> 14) & 3);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="device_type">Type of device</param>
        /// <param name="function">Function number</param>
        /// <param name="method">Buffering method</param>
        /// <param name="access">Access of file handle</param>
        public NtIoControlCode(FileDeviceType device_type, int function, FileControlMethod method, FileControlAccess access)
        {
            _control_code = (((int)device_type) << 16) | (((int)access) << 14) | (function << 2) | ((int)method);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="code">Raw IO control code to convert.</param>
        public NtIoControlCode(int code)
        {
            _control_code = code;
        }

        /// <summary>
        /// Static method to create an NtIoControlCode 
        /// </summary>
        /// <param name="code">The conde as an integer.</param>
        /// <returns>The io control code.</returns>
        public static NtIoControlCode ToControlCode(int code)
        {
            return new NtIoControlCode(code);
        }

        /// <summary>
        /// Convert the io control code to an Int32
        /// </summary>
        /// <returns>The int32 version of the code</returns>
        public int ToInt32()
        {
            return _control_code;
        }
    }

    public static class NtWellKnownIoControlCodes
    {
        public static readonly NtIoControlCode FSCTL_REQUEST_OPLOCK_LEVEL_1 = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 0, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_REQUEST_OPLOCK_LEVEL_2 = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 1, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_REQUEST_BATCH_OPLOCK = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 2, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_OPLOCK_BREAK_ACKNOWLEDGE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 3, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_OPBATCH_ACK_CLOSE_PENDING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 4, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_OPLOCK_BREAK_NOTIFY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 5, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_LOCK_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 6, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_UNLOCK_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 7, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DISMOUNT_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 8, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_IS_VOLUME_MOUNTED = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 10, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_IS_PATHNAME_VALID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 11, FileControlMethod.Buffered, FileControlAccess.Any); // PATHNAME_BUFFER,
        public static readonly NtIoControlCode FSCTL_MARK_VOLUME_DIRTY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 12, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_RETRIEVAL_POINTERS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 14, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_COMPRESSION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 15, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_COMPRESSION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 16, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_SET_BOOTLOADER_ACCESSED = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 19, FileControlMethod.Neither, FileControlAccess.Any);
        //#define FSCTL_MARK_AS_SYSTEM_HIVE       FSCTL_SET_BOOTLOADER_ACCESSED
        public static readonly NtIoControlCode FSCTL_OPLOCK_BREAK_ACK_NO_2 = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 20, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_INVALIDATE_VOLUMES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 21, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_FAT_BPB = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 22, FileControlMethod.Buffered, FileControlAccess.Any); // FSCTL_QUERY_FAT_BPB_BUFFER
        public static readonly NtIoControlCode FSCTL_REQUEST_FILTER_OPLOCK = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 23, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_FILESYSTEM_GET_STATISTICS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 24, FileControlMethod.Buffered, FileControlAccess.Any); // FILESYSTEM_STATISTICS
        public static readonly NtIoControlCode FSCTL_GET_NTFS_VOLUME_DATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 25, FileControlMethod.Buffered, FileControlAccess.Any); // NTFS_VOLUME_DATA_BUFFER
        public static readonly NtIoControlCode FSCTL_GET_NTFS_FILE_RECORD = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 26, FileControlMethod.Buffered, FileControlAccess.Any); // NTFS_FILE_RECORD_INPUT_BUFFER, NTFS_FILE_RECORD_OUTPUT_BUFFER
        public static readonly NtIoControlCode FSCTL_GET_VOLUME_BITMAP = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 27, FileControlMethod.Neither, FileControlAccess.Any); // STARTING_LCN_INPUT_BUFFER, VOLUME_BITMAP_BUFFER
        public static readonly NtIoControlCode FSCTL_GET_RETRIEVAL_POINTERS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 28, FileControlMethod.Neither, FileControlAccess.Any); // STARTING_VCN_INPUT_BUFFER, RETRIEVAL_POINTERS_BUFFER
        public static readonly NtIoControlCode FSCTL_MOVE_FILE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 29, FileControlMethod.Buffered, FileControlAccess.Any); // MOVE_FILE_DATA,
        public static readonly NtIoControlCode FSCTL_IS_VOLUME_DIRTY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 30, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_ALLOW_EXTENDED_DASD_IO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 32, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_FIND_FILES_BY_SID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 35, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_OBJECT_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 38, FileControlMethod.Buffered, FileControlAccess.Any); // FILE_OBJECTID_BUFFER
        public static readonly NtIoControlCode FSCTL_GET_OBJECT_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 39, FileControlMethod.Buffered, FileControlAccess.Any); // FILE_OBJECTID_BUFFER
        public static readonly NtIoControlCode FSCTL_DELETE_OBJECT_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 40, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_REPARSE_POINT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 41, FileControlMethod.Buffered, FileControlAccess.Any); // REPARSE_DATA_BUFFER,
        public static readonly NtIoControlCode FSCTL_GET_REPARSE_POINT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 42, FileControlMethod.Buffered, FileControlAccess.Any); // REPARSE_DATA_BUFFER
        public static readonly NtIoControlCode FSCTL_DELETE_REPARSE_POINT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 43, FileControlMethod.Buffered, FileControlAccess.Any); // REPARSE_DATA_BUFFER,
        public static readonly NtIoControlCode FSCTL_ENUM_USN_DATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 44, FileControlMethod.Neither, FileControlAccess.Any); // MFT_ENUM_DATA,
        public static readonly NtIoControlCode FSCTL_SECURITY_ID_CHECK = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 45, FileControlMethod.Neither, FileControlAccess.Read);  // BULK_SECURITY_TEST_DATA,
        public static readonly NtIoControlCode FSCTL_READ_USN_JOURNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 46, FileControlMethod.Neither, FileControlAccess.Any); // READ_USN_JOURNAL_DATA, USN
        public static readonly NtIoControlCode FSCTL_SET_OBJECT_ID_EXTENDED = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 47, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CREATE_OR_GET_OBJECT_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 48, FileControlMethod.Buffered, FileControlAccess.Any); // FILE_OBJECTID_BUFFER
        public static readonly NtIoControlCode FSCTL_SET_SPARSE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 49, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_ZERO_DATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 50, FileControlMethod.Buffered, FileControlAccess.Write); // FILE_ZERO_DATA_INFORMATION,
        public static readonly NtIoControlCode FSCTL_QUERY_ALLOCATED_RANGES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 51, FileControlMethod.Neither, FileControlAccess.Read);  // FILE_ALLOCATED_RANGE_BUFFER, FILE_ALLOCATED_RANGE_BUFFER
        public static readonly NtIoControlCode FSCTL_ENABLE_UPGRADE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 52, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_SET_ENCRYPTION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 53, FileControlMethod.Neither, FileControlAccess.Any); // ENCRYPTION_BUFFER, DECRYPTION_STATUS_BUFFER
        public static readonly NtIoControlCode FSCTL_ENCRYPTION_FSCTL_IO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 54, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_WRITE_RAW_ENCRYPTED = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 55, FileControlMethod.Neither, FileControlAccess.Any); // ENCRYPTED_DATA_INFO, EXTENDED_ENCRYPTED_DATA_INFO
        public static readonly NtIoControlCode FSCTL_READ_RAW_ENCRYPTED = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 56, FileControlMethod.Neither, FileControlAccess.Any); // REQUEST_RAW_ENCRYPTED_DATA, ENCRYPTED_DATA_INFO, EXTENDED_ENCRYPTED_DATA_INFO
        public static readonly NtIoControlCode FSCTL_CREATE_USN_JOURNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 57, FileControlMethod.Neither, FileControlAccess.Any); // CREATE_USN_JOURNAL_DATA,
        public static readonly NtIoControlCode FSCTL_READ_FILE_USN_DATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 58, FileControlMethod.Neither, FileControlAccess.Any); // Read the Usn Record for a file
        public static readonly NtIoControlCode FSCTL_WRITE_USN_CLOSE_RECORD = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 59, FileControlMethod.Neither, FileControlAccess.Any); // Generate Close Usn Record
        public static readonly NtIoControlCode FSCTL_EXTEND_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 60, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_USN_JOURNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 61, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DELETE_USN_JOURNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 62, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_MARK_HANDLE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 63, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SIS_COPYFILE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 64, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SIS_LINK_FILES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 65, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_RECALL_FILE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 69, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_READ_FROM_PLEX = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 71, FileControlMethod.OutDirect, FileControlAccess.Read);
        public static readonly NtIoControlCode FSCTL_FILE_PREFETCH = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 72, FileControlMethod.Buffered, FileControlAccess.Any); // FILE_PREFETCH
        public static readonly NtIoControlCode FSCTL_MAKE_MEDIA_COMPATIBLE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 76, FileControlMethod.Buffered, FileControlAccess.Write); // UDFS R/W
        public static readonly NtIoControlCode FSCTL_SET_DEFECT_MANAGEMENT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 77, FileControlMethod.Buffered, FileControlAccess.Write); // UDFS R/W
        public static readonly NtIoControlCode FSCTL_QUERY_SPARING_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 78, FileControlMethod.Buffered, FileControlAccess.Any); // UDFS R/W
        public static readonly NtIoControlCode FSCTL_QUERY_ON_DISK_VOLUME_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 79, FileControlMethod.Buffered, FileControlAccess.Any); // C/UDFS
        public static readonly NtIoControlCode FSCTL_SET_VOLUME_COMPRESSION_STATE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 80, FileControlMethod.Buffered, FileControlAccess.Any); // VOLUME_COMPRESSION_STATE
        public static readonly NtIoControlCode FSCTL_TXFS_MODIFY_RM = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 81, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_QUERY_RM_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 82, FileControlMethod.Buffered, FileControlAccess.Read);  // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_ROLLFORWARD_REDO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 84, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_ROLLFORWARD_UNDO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 85, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_START_RM = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 86, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_SHUTDOWN_RM = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 87, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_READ_BACKUP_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 88, FileControlMethod.Buffered, FileControlAccess.Read);  // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_WRITE_BACKUP_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 89, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_CREATE_SECONDARY_RM = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 90, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_GET_METADATA_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 91, FileControlMethod.Buffered, FileControlAccess.Read);  // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_GET_TRANSACTED_VERSION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 92, FileControlMethod.Buffered, FileControlAccess.Read);  // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_SAVEPOINT_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 94, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_CREATE_MINIVERSION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 95, FileControlMethod.Buffered, FileControlAccess.Write); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_TRANSACTION_ACTIVE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 99, FileControlMethod.Buffered, FileControlAccess.Read);  // TxF
        public static readonly NtIoControlCode FSCTL_SET_ZERO_ON_DEALLOCATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 101, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_REPAIR = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 102, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_REPAIR = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 103, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_WAIT_FOR_REPAIR = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 104, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_INITIATE_REPAIR = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 106, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSC_INTERNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 107, FileControlMethod.Neither, FileControlAccess.Any); // CSC internal implementation
        public static readonly NtIoControlCode FSCTL_SHRINK_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 108, FileControlMethod.Buffered, FileControlAccess.Any); // SHRINK_VOLUME_INFORMATION
        public static readonly NtIoControlCode FSCTL_SET_SHORT_NAME_BEHAVIOR = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 109, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DFSR_SET_GHOST_HANDLE_STATE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 110, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 120, FileControlMethod.Buffered, FileControlAccess.Read); // TxF
        public static readonly NtIoControlCode FSCTL_TXFS_LIST_TRANSACTIONS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 121, FileControlMethod.Buffered, FileControlAccess.Read); // TxF
        public static readonly NtIoControlCode FSCTL_QUERY_PAGEFILE_ENCRYPTION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 122, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_RESET_VOLUME_ALLOCATION_HINTS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 123, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_DEPENDENT_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 124, FileControlMethod.Buffered, FileControlAccess.Any);    // Dependency File System Filter
        public static readonly NtIoControlCode FSCTL_SD_GLOBAL_CHANGE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 125, FileControlMethod.Buffered, FileControlAccess.Any); // Query/Change NTFS Security Descriptors
        public static readonly NtIoControlCode FSCTL_TXFS_READ_BACKUP_INFORMATION2 = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 126, FileControlMethod.Buffered, FileControlAccess.Any); // TxF
        public static readonly NtIoControlCode FSCTL_LOOKUP_STREAM_FROM_CLUSTER = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 127, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_TXFS_WRITE_BACKUP_INFORMATION2 = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 128, FileControlMethod.Buffered, FileControlAccess.Any); // TxF
        public static readonly NtIoControlCode FSCTL_FILE_TYPE_NOTIFICATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 129, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_FILE_LEVEL_TRIM = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 130, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_GET_BOOT_AREA_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 140, FileControlMethod.Buffered, FileControlAccess.Any); // BOOT_AREA_INFO
        public static readonly NtIoControlCode FSCTL_GET_RETRIEVAL_POINTER_BASE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 141, FileControlMethod.Buffered, FileControlAccess.Any); // RETRIEVAL_POINTER_BASE
        public static readonly NtIoControlCode FSCTL_SET_PERSISTENT_VOLUME_STATE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 142, FileControlMethod.Buffered, FileControlAccess.Any);  // FILE_FS_PERSISTENT_VOLUME_INFORMATION
        public static readonly NtIoControlCode FSCTL_QUERY_PERSISTENT_VOLUME_STATE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 143, FileControlMethod.Buffered, FileControlAccess.Any);  // FILE_FS_PERSISTENT_VOLUME_INFORMATION
        public static readonly NtIoControlCode FSCTL_REQUEST_OPLOCK = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 144, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_TUNNEL_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 145, FileControlMethod.Buffered, FileControlAccess.Any); // CSV_TUNNEL_REQUEST
        public static readonly NtIoControlCode FSCTL_IS_CSV_FILE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 146, FileControlMethod.Buffered, FileControlAccess.Any); // IS_CSV_FILE
        public static readonly NtIoControlCode FSCTL_QUERY_FILE_SYSTEM_RECOGNITION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 147, FileControlMethod.Buffered, FileControlAccess.Any); //
        public static readonly NtIoControlCode FSCTL_CSV_GET_VOLUME_PATH_NAME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 148, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_GET_VOLUME_NAME_FOR_VOLUME_MOUNT_POINT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 149, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_GET_VOLUME_PATH_NAMES_FOR_VOLUME_NAME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 150, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_IS_FILE_ON_CSV_VOLUME = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 151, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CORRUPTION_HANDLING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 152, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_OFFLOAD_READ = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 153, FileControlMethod.Buffered, FileControlAccess.Read);
        public static readonly NtIoControlCode FSCTL_OFFLOAD_WRITE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 154, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_CSV_INTERNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 155, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_PURGE_FAILURE_MODE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 156, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_FILE_LAYOUT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 157, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_IS_VOLUME_OWNED_BYCSVFS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 158, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_INTEGRITY_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 159, FileControlMethod.Buffered, FileControlAccess.Any);                  // FSCTL_GET_INTEGRITY_INFORMATION_BUFFER
        public static readonly NtIoControlCode FSCTL_SET_INTEGRITY_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 160, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write); // FSCTL_SET_INTEGRITY_INFORMATION_BUFFER
        public static readonly NtIoControlCode FSCTL_QUERY_FILE_REGIONS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 161, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DEDUP_FILE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 165, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DEDUP_QUERY_FILE_HASHES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 166, FileControlMethod.Neither, FileControlAccess.Read);
        public static readonly NtIoControlCode FSCTL_DEDUP_QUERY_RANGE_STATE = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 167, FileControlMethod.Neither, FileControlAccess.Read);
        public static readonly NtIoControlCode FSCTL_DEDUP_QUERY_REPARSE_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 168, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_RKF_INTERNAL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 171, FileControlMethod.Neither, FileControlAccess.Any); // Resume Key Filter
        public static readonly NtIoControlCode FSCTL_SCRUB_DATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 172, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_REPAIR_COPIES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 173, FileControlMethod.Buffered, FileControlAccess.Read | FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_DISABLE_LOCAL_BUFFERING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 174, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_MGMT_LOCK = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 175, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_QUERY_DOWN_LEVEL_FILE_SYSTEM_CHARACTERISTICS = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 176, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_ADVANCE_FILE_ID = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 177, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_SYNC_TUNNEL_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 178, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_QUERY_VETO_FILE_DIRECT_IO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 179, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_WRITE_USN_REASON = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 180, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_CONTROL = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 181, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_REFS_VOLUME_DATA = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 182, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_CSV_H_BREAKING_SYNC_TUNNEL_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 185, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_STORAGE_CLASSES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 187, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_QUERY_REGION_INFO = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 188, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_USN_TRACK_MODIFIED_RANGES = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 189, FileControlMethod.Buffered, FileControlAccess.Any); // USN_TRACK_MODIFIED_RANGES
        public static readonly NtIoControlCode FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 192, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SVHDX_SYNC_TUNNEL_REQUEST = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 193, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SVHDX_SET_INITIATOR_INFORMATION = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 194, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_SET_EXTERNAL_BACKING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 195, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_GET_EXTERNAL_BACKING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 196, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_DELETE_EXTERNAL_BACKING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 197, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_ENUM_EXTERNAL_BACKING = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 198, FileControlMethod.Buffered, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_ENUM_OVERLAY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 199, FileControlMethod.Neither, FileControlAccess.Any);
        public static readonly NtIoControlCode FSCTL_ADD_OVERLAY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 204, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_REMOVE_OVERLAY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 205, FileControlMethod.Buffered, FileControlAccess.Write);
        public static readonly NtIoControlCode FSCTL_UPDATE_OVERLAY = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 206, FileControlMethod.Buffered, FileControlAccess.Write);
    }

    public enum ReparseTag : uint
    {
        MOUNT_POINT = 0xA0000003,
        HSM = 0xC0000004,
        DRIVE_EXTENDER = 0x80000005,
        HSM2 = 0x80000006,
        SIS = 0x80000007,
        WIM = 0x80000008,
        CSV = 0x80000009,
        DFS = 0x8000000A,
        FILTER_MANAGER = 0x8000000B,
        SYMLINK = 0xA000000C,
        IIS_CACHE = 0xA0000010,
        DFSR = 0x80000012,
        DEDUP = 0x80000013,
        APPXSTRM = 0xC0000014,
        NFS = 0x80000014,
        FILE_PLACEHOLDER = 0x80000015,
        DFM = 0x80000016,
        WOF = 0x80000017,
    }

    public abstract class ReparseBuffer
    {
        public ReparseTag Tag { get; private set; }

        protected abstract void ParseBuffer(int data_length, BinaryReader reader);
        protected abstract byte[] GetBuffer();

        protected ReparseBuffer(ReparseTag tag)
        {
            Tag = tag;
        }

        public static ReparseBuffer FromByteArray(byte[] ba)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(ba));
            ReparseTag tag = (ReparseTag)reader.ReadUInt32();
            int data_length = reader.ReadUInt16();
            // Reserved
            reader.ReadUInt16();

            ReparseBuffer buffer = null;

            switch (tag)
            {
                case ReparseTag.MOUNT_POINT:
                    buffer = new MountPointReparseBuffer();
                    break;
                case ReparseTag.SYMLINK:
                    buffer = new SymlinkReparseBuffer();
                    break;
                default:
                    buffer = new GenericReparseBuffer(tag);
                    break;
            }

            buffer.ParseBuffer(data_length, reader);
            return buffer;
        }

        public byte[] ToByteArray()
        {
            byte[] buffer = GetBuffer();
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write((uint)Tag);
            if (buffer.Length > ushort.MaxValue)
            {
                throw new ArgumentException("Reparse buffer too large");
            }
            writer.Write((ushort)buffer.Length);
            writer.Write((ushort)0);
            writer.Write(buffer);
            return stm.ToArray();
        }
    }

    public sealed class GenericReparseBuffer : ReparseBuffer
    {
        public GenericReparseBuffer(ReparseTag tag, byte[] data) : base(tag)
        {
            Data = (byte[])data.Clone();
        }

        internal GenericReparseBuffer(ReparseTag tag) : base(tag)
        {
        }

        public byte[] Data { get; private set; }

        protected override byte[] GetBuffer()
        {
            return Data;
        }

        protected override void ParseBuffer(int data_length, BinaryReader reader)
        {
            Data = reader.ReadAllBytes(data_length);
        }
    }

    public sealed class MountPointReparseBuffer : ReparseBuffer
    {
        public MountPointReparseBuffer(string substitution_name, string print_name) : base(ReparseTag.MOUNT_POINT)
        {
            if (String.IsNullOrEmpty(substitution_name))
            {
                throw new ArgumentException("substitution_name");
            }
            SubstitutionName = substitution_name;
            PrintName = print_name ?? String.Empty;
        }

        internal MountPointReparseBuffer() : base(ReparseTag.MOUNT_POINT)
        {
        }

        public string SubstitutionName { get; private set; }
        public string PrintName { get; private set; }
        
        protected override void ParseBuffer(int data_length, BinaryReader reader)
        {
            int subname_ofs = reader.ReadUInt16();
            int subname_len = reader.ReadUInt16();
            int pname_ofs = reader.ReadUInt16();
            int pname_len = reader.ReadUInt16();

            byte[] path_buffer = reader.ReadAllBytes(data_length - 8);
            SubstitutionName = Encoding.Unicode.GetString(path_buffer, subname_ofs, subname_len);
            PrintName = Encoding.Unicode.GetString(path_buffer, pname_ofs, pname_len);
        }

        protected override byte[] GetBuffer()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            byte[] subname = Encoding.Unicode.GetBytes(SubstitutionName);
            byte[] pname = Encoding.Unicode.GetBytes(PrintName);
            // SubstituteNameOffset
            writer.Write((ushort)0);
            // SubstituteNameLength
            writer.Write((ushort)subname.Length);
            // PrintNameOffset
            writer.Write((ushort)(subname.Length + 2));
            // PrintNameLength
            writer.Write((ushort)pname.Length);
            writer.Write(subname);
            writer.Write(new byte[2]);
            writer.Write(pname);
            writer.Write(new byte[2]);
            return stm.ToArray();
        }
    }

    public enum SymlinkReparseBufferFlags
    {
        None = 0,
        Relative = 1,
    }

    public sealed class SymlinkReparseBuffer : ReparseBuffer
    {
        public SymlinkReparseBuffer(string substitution_name, 
            string print_name, SymlinkReparseBufferFlags flags) 
            : base(ReparseTag.SYMLINK)
        {
            if (String.IsNullOrEmpty(substitution_name))
            {
                throw new ArgumentException("substitution_name");
            }

            if (String.IsNullOrEmpty(print_name))
            {
                throw new ArgumentException("print_name");
            }
            
            SubstitutionName = substitution_name;
            PrintName = print_name;
            Flags = flags;
        }

        internal SymlinkReparseBuffer() : base(ReparseTag.SYMLINK)
        {
        }

        public string SubstitutionName { get; private set; }
        public string PrintName { get; private set; }
        public SymlinkReparseBufferFlags Flags { get; private set; }

        protected override void ParseBuffer(int data_length, BinaryReader reader)
        {
            int subname_ofs = reader.ReadUInt16();
            int subname_len = reader.ReadUInt16();
            int pname_ofs = reader.ReadUInt16();
            int pname_len = reader.ReadUInt16();

            Flags = (SymlinkReparseBufferFlags)reader.ReadInt32();

            byte[] path_buffer = reader.ReadAllBytes(data_length - 12);
            SubstitutionName = Encoding.Unicode.GetString(path_buffer, subname_ofs, subname_len);
            PrintName = Encoding.Unicode.GetString(path_buffer, pname_ofs, pname_len);
        }

        protected override byte[] GetBuffer()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            byte[] subname = Encoding.Unicode.GetBytes(SubstitutionName);
            byte[] pname = Encoding.Unicode.GetBytes(PrintName);
            // SubstituteNameOffset
            writer.Write((ushort)0);
            // SubstituteNameLength
            writer.Write((ushort)subname.Length);
            // PrintNameOffset
            writer.Write((ushort)(subname.Length + 2));
            // PrintNameLength
            writer.Write((ushort)pname.Length);
            writer.Write((int)Flags);
            writer.Write(subname);
            writer.Write(new byte[2]);
            writer.Write(pname);
            writer.Write(new byte[2]);
            return stm.ToArray();
        }
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
                return HasAttributes(FileAttributes.RepasePoint);
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

    internal sealed class NtFileResult : IDisposable
    {
        private NtFile _file;
        private NtEvent _event;
        private SafeIoStatusBuffer _io_status;
        private IoStatus _result;

        internal NtFileResult(NtFile file)
        {
            _file = file;
            if (!_file.CanSynchronize)
            {
                _event = NtEvent.Create(null, 
                    EventType.SynchronizationEvent, false);
            }
            _io_status = new SafeIoStatusBuffer();
            _result = null;
        }

        internal SafeKernelObjectHandle EventHandle
        {
            get { return _event != null ? _event.Handle : SafeKernelObjectHandle.Null; }
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
            else if (status == NtStatus.STATUS_SUCCESS)
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
                else if (status == NtStatus.STATUS_SUCCESS)
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
                status = _file.Wait(NtWaitTimeout.Infinite).ToNtException();
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

            using (NtWaitHandle wait_handle = _event != null ? _event.DuplicateAsWaitHandle() : _file.DuplicateAsWaitHandle())
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
            IoStatus io_status = new IoStatus();
            NtSystemCalls.NtCancelIoFileEx(_file.Handle, 
                _io_status, io_status).ToNtException();
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

#pragma warning restore 1591

    /// <summary>
    /// Class representing a NT File object
    /// </summary>
    [NtType("File"), NtType("Device")]
    public class NtFile : NtObjectWithDuplicate<NtFile, FileAccessRights>
    {
        // Cancellation source for stopping pending IO on close.
        private CancellationTokenSource _cts;

        internal NtFile(SafeKernelObjectHandle handle, IoStatus io_status) : base(handle)
        {
            _cts = new CancellationTokenSource();
            OpenResult = io_status != null ? (FileOpenResult)io_status.Information.ToInt32() : FileOpenResult.Opened;
        }

        internal NtFile(SafeKernelObjectHandle handle) 
            : this(handle, null)
        {
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
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtFile> Create(ObjectAttributes obj_attributes, FileAccessRights desired_access, FileAttributes file_attributes, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer, bool throw_on_error)
        {            
            SafeKernelObjectHandle handle;
            IoStatus iostatus = new IoStatus();
            byte[] buffer = ea_buffer != null ? ea_buffer.ToByteArray() : null;
            return NtSystemCalls.NtCreateFile(out handle, desired_access, obj_attributes, iostatus, null, FileAttributes.Normal,
                share_access, disposition, open_options, 
                buffer, buffer != null ? buffer.Length : 0).CreateResult(throw_on_error, () => new NtFile(handle, iostatus));
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
        public static NtResult<NtFile> CreateNamedPipe(ObjectAttributes obj_attributes, FileAccessRights desired_access,
            FileShareMode share_access, FileOpenOptions open_options, FileDisposition disposition, NamedPipeType pipe_type,
            NamedPipeReadMode read_mode, NamedPipeCompletionMode completion_mode, int maximum_instances, int input_quota,
            int output_quota, NtWaitTimeout default_timeout, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            IoStatus io_status = new IoStatus();
            return NtSystemCalls.NtCreateNamedPipeFile(out handle, desired_access, obj_attributes, io_status, share_access, disposition, open_options,
                pipe_type, read_mode, completion_mode, maximum_instances, input_quota, output_quota, default_timeout.Timeout)
                .CreateResult(throw_on_error, () => new NtFile(handle, io_status));
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
        public static NtFile CreateNamedPipe(ObjectAttributes obj_attributes, FileAccessRights desired_access,
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
        /// <returns>The file instance for the pipe.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtFile CreateNamedPipe(string name, NtObject root, FileAccessRights desired_access,
            FileShareMode share_access, FileOpenOptions open_options, FileDisposition disposition, NamedPipeType pipe_type,
            NamedPipeReadMode read_mode, NamedPipeCompletionMode completion_mode, int maximum_instances, int input_quota,
            int output_quota, NtWaitTimeout default_timeout)
        {
            using (ObjectAttributes obj_attributes = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return CreateNamedPipe(obj_attributes, desired_access, share_access, open_options, disposition, pipe_type,
                    read_mode, completion_mode, maximum_instances, input_quota, output_quota, default_timeout);
            }
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
            SafeKernelObjectHandle handle;
            IoStatus io_status = new IoStatus();
            LargeInteger timeout = default_timeout < 0 ? new LargeInteger(-1) : NtWaitTimeout.FromMilliseconds(default_timeout).Timeout;
            NtSystemCalls.NtCreateMailslotFile(out handle, desired_access, obj_attributes, io_status, open_options, mailslot_quota, maximum_message_size, timeout);
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

        static IntPtr GetSafePointer(SafeBuffer buffer)
        {
            return buffer != null ? buffer.DangerousGetHandle() : IntPtr.Zero;
        }

        static int GetSafeLength(SafeBuffer buffer)
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

        private async Task<int> IoControlGenericAsync(IoControlFunction func, 
                        NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer, CancellationToken token)
        {
            using (var linked_cts = CancellationTokenSource.CreateLinkedTokenSource(token, _cts.Token))
            {
                using (NtFileResult result = new NtFileResult(this))
                {
                    NtStatus status = await result.CompleteCallAsync(func(Handle, result.EventHandle, IntPtr.Zero, IntPtr.Zero, result.IoStatusBuffer,
                        control_code.ToInt32(), GetSafePointer(input_buffer), GetSafeLength(input_buffer), 
                        GetSafePointer(output_buffer), GetSafeLength(output_buffer)), linked_cts.Token);
                    if (status == NtStatus.STATUS_PENDING)
                    {
                        result.Cancel();
                        throw new NtException(NtStatus.STATUS_CANCELLED);
                    }
                    status.ToNtException();
                    return result.Information32;
                }
            }
        }

        private async Task<byte[]> IoControlGenericAsync(IoControlFunction func, NtIoControlCode control_code, byte[] input_buffer, int max_output, CancellationToken token)
        {
            using (SafeHGlobalBuffer input = input_buffer != null ? new SafeHGlobalBuffer(input_buffer) : null)
            {
                using (SafeHGlobalBuffer output = max_output > 0 ? new SafeHGlobalBuffer(max_output) : null)
                {
                    int output_length = await IoControlGenericAsync(func, control_code, input, output, token);
                    if (output != null)
                    {
                        return output.ReadBytes(output_length);
                    }
                    return new byte[0];
                }
            }
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
            return IoControlGenericAsync(NtSystemCalls.NtDeviceIoControlFile, control_code, input_buffer, output_buffer, token);
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
            return IoControlGenericAsync(NtSystemCalls.NtDeviceIoControlFile, control_code, input_buffer, max_output, token);
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
            return IoControlGenericAsync(NtSystemCalls.NtFsControlFile, control_code, input_buffer, output_buffer, token);
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
            return IoControlGenericAsync(NtSystemCalls.NtFsControlFile, control_code, input_buffer, max_output, token);
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

        private int IoControlGeneric(IoControlFunction func, NtIoControlCode control_code, SafeBuffer input_buffer, SafeBuffer output_buffer)
        {
            using (NtFileResult result = new NtFileResult(this))
            {
                NtStatus status = result.CompleteCall(func(Handle, result.EventHandle, IntPtr.Zero, IntPtr.Zero, result.IoStatusBuffer,
                    control_code.ToInt32(), GetSafePointer(input_buffer), GetSafeLength(input_buffer), GetSafePointer(output_buffer), 
                    GetSafeLength(output_buffer))).ToNtException();
                return result.Information32;
            }
        }

        private byte[] IoControlGeneric(IoControlFunction func, NtIoControlCode control_code, byte[] input_buffer, int max_output)
        {
            using (SafeHGlobalBuffer input = input_buffer != null ? new SafeHGlobalBuffer(input_buffer) : null)
            {
                using (SafeHGlobalBuffer output = max_output > 0 ? new SafeHGlobalBuffer(max_output) : null)
                {
                    int output_length = IoControlGeneric(func, control_code, input, output);
                    if (output != null)
                    {
                        return output.ReadBytes(output_length);
                    }
                    return new byte[0];
                }
            }
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
            return IoControlGeneric(NtSystemCalls.NtDeviceIoControlFile, control_code, input_buffer, output_buffer);
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
            return IoControlGeneric(NtSystemCalls.NtDeviceIoControlFile, control_code, input_buffer, max_output);
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
            return IoControlGeneric(NtSystemCalls.NtFsControlFile, control_code, input_buffer, output_buffer);
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
            return IoControlGeneric(NtSystemCalls.NtFsControlFile, control_code, input_buffer, max_output);
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
            SafeKernelObjectHandle handle;
            IoStatus iostatus = new IoStatus();
            return NtSystemCalls.NtOpenFile(out handle, desired_access, obj_attributes, iostatus, share_access, open_options)
                .CreateResult(throw_on_error, () => new NtFile(handle, iostatus));
        }

        internal static NtResult<NtObject> FromName(ObjectAttributes object_attributes, AccessMask desired_access, bool throw_on_error)
        {
            return Open(object_attributes, desired_access.ToSpecificAccess<FileAccessRights>(), FileShareMode.Read | FileShareMode.Delete, 
                FileOpenOptions.None, throw_on_error).Cast<NtObject>();
        }

        /// <summary>
        /// Open a file
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>
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
        /// <returns>The opened file</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtFile Open(string path, NtObject root, FileAccessRights desired_access, 
            FileShareMode shared_access, FileOpenOptions open_options)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access, shared_access, open_options);
            }
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
        /// Get object ID for current file
        /// </summary>
        /// <returns>The object ID as a string</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public string FileId
        {
            get
            {
                var internal_info = QueryFileFixed<FileInternalInformation>(FileInformationClass.FileInternalInformation);
                return NtFileUtils.FileIdToString(internal_info.IndexNumber.QuadPart);
            }
        }
        
        /// <summary>
        /// Get the attributes of a file.
        /// </summary>
        /// <returns>The file attributes</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public FileAttributes FileAttributes
        {
            get
            {
                return QueryFileFixed<FileBasicInformation>(FileInformationClass.FileBasicInformation).FileAttributes;
            }
        }

        /// <summary>
        /// Get whether this file represents a directory.
        /// </summary>
        public bool IsDirectory
        {
            get
            {
                return (FileAttributes & FileAttributes.Directory) == FileAttributes.Directory;
            }
        }

        /// <summary>
        /// Get whether this file repsents a reparse point.
        /// </summary>
        public bool IsReparsePoint
        {
            get
            {
                return (FileAttributes & FileAttributes.RepasePoint) == FileAttributes.RepasePoint;
            }
        }

        /// <summary>
        /// The result of opening the file, whether it was created, overwritten etc.
        /// </summary>
        public FileOpenResult OpenResult
        {
            get; private set;
        }

        /// <summary>
        /// Get the object ID of a file as a string
        /// </summary>
        /// <param name="path">The path to the file</param>
        /// <returns>The object ID as a string</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static string GetFileId(string path)
        {
            using (NtFile file = NtFile.Open(path, null, FileAccessRights.MaximumAllowed, FileShareMode.None, FileOpenOptions.None))
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
                SafeKernelObjectHandle handle;
                IoStatus iostatus = new IoStatus();
                return NtSystemCalls.NtOpenFile(out handle, desired_access, obja,
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
        /// Delete the file. Must have been opened with DELETE access.
        /// </summary>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Delete()
        {
            SetFileFixed(new FileDispositionInformation() { DeleteFile = true }, FileInformationClass.FileDispositionInformation);
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

        private void DoLinkRename(FileInformationClass file_info, string linkname, NtFile root)
        {
            FileLinkRenameInformation link = new FileLinkRenameInformation();
            link.ReplaceIfExists = true;
            link.RootDirectory = root != null ? root.Handle.DangerousGetHandle() : IntPtr.Zero;
            char[] chars = linkname.ToCharArray();
            link.FileNameLength = chars.Length * 2;
            using (var buffer = link.ToBuffer(link.FileNameLength, true))
            {
                IoStatus iostatus = new IoStatus();
                buffer.Data.WriteArray(0, chars, 0, chars.Length);
                NtSystemCalls.NtSetInformationFile(Handle, iostatus, buffer,
                        buffer.Length, file_info).ToNtException();
            }
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
        /// Rename file.
        /// </summary>
        /// <param name="new_name">The target NT path.</param>
        /// <param name="root">The root directory if new_name is relative</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Rename(string new_name, NtFile root)
        {
            DoLinkRename(FileInformationClass.FileRenameInformation, new_name, root);
        }

        /// <summary>
        /// Rename this file with an absolute path.
        /// </summary>
        /// <param name="new_name">The target absolute NT path.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Rename(string new_name)
        {
            DoLinkRename(FileInformationClass.FileRenameInformation, new_name, null);
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
        /// Create a mount point.
        /// </summary>
        /// <param name="path">The path to the mount point to create.</param>
        /// <param name="substitute_name">The substitute name to reparse to.</param>
        /// <param name="print_name">The print name to display (can be null).</param>
        public static void CreateMountPoint(string path, string substitute_name, string print_name)
        {
            using (NtFile file = NtFile.Create(path, FileAccessRights.Synchronize | FileAccessRights.MaximumAllowed,
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
            using (NtFile file = NtFile.Create(path, FileAccessRights.Synchronize | FileAccessRights.MaximumAllowed,
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
        /// <returns>The reparse point buffer.</returns>
        public ReparseBuffer GetReparsePoint()
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(16 * 1024))
            {
                FsControl(NtWellKnownIoControlCodes.FSCTL_GET_REPARSE_POINT, null, buffer);

                return ReparseBuffer.FromByteArray(buffer.ToArray());
            }
        }

        /// <summary>
        /// Get the reparse point buffer for the file.
        /// </summary>
        /// <param name="path">The path to the reparse point.</param>
        /// <returns>The reparse point buffer.</returns>
        public static ReparseBuffer GetReparsePoint(string path)
        {
            using (NtFile file = NtFile.Open(path, null, FileAccessRights.Synchronize | FileAccessRights.MaximumAllowed,
                FileShareMode.None, FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenReparsePoint))
            {
                return file.GetReparsePoint();
            }
        }

        /// <summary>
        /// Delete the reparse point buffer
        /// </summary>
        /// <returns>The original reparse buffer.</returns>
        public ReparseBuffer DeleteReparsePoint()
        {
            ReparseBuffer reparse = GetReparsePoint();
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(new GenericReparseBuffer(reparse.Tag, new byte[0]).ToByteArray()))
            {
                FsControl(NtWellKnownIoControlCodes.FSCTL_DELETE_REPARSE_POINT, buffer, null);
            }
            return reparse;
        }

        /// <summary>
        /// Delete the reparse point buffer.
        /// </summary>
        /// <param name="path">The path to the reparse point.</param>
        /// <returns>The original reparse buffer.</returns>
        public static ReparseBuffer DeleteReparsePoint(string path)
        {
            using (NtFile file = NtFile.Open(path, null, FileAccessRights.Synchronize | FileAccessRights.MaximumAllowed,
                FileShareMode.None, FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenReparsePoint))
            {
                return file.DeleteReparsePoint();
            }
        }

        /// <summary>
        /// Get list of accessible files underneath a directory.
        /// </summary>
        /// <param name="share_access">Share access for file open</param>
        /// <param name="open_options">Options for open call.</param>
        /// <param name="desired_access">The desired access for each file.</param>
        /// <returns>The list of files which can be access.</returns>
        public IEnumerable<NtFile> QueryAccessibleFiles(FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options)
        {
            using (var list = new DisposableList<NtFile>())
            {
                foreach (var entry in QueryDirectoryInfo())
                {
                    using (ObjectAttributes obja = new ObjectAttributes(entry.FileName, AttributeFlags.CaseInsensitive, this))
                    {
                        var result = Open(obja, desired_access, share_access, open_options, false);
                        if (result.IsSuccess)
                        {
                            list.Add(result.Result);
                        }
                    }
                }
                return new List<NtFile>(list.ToArrayAndClear());
            }
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
            UnicodeString mask = file_mask != null ? new UnicodeString(file_mask) : null;
            // 32k seems to be a reasonable size, too big and some volumes will fail with STATUS_INVALID_PARAMETER.
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(32 * 1024))
            {
                using (NtFileResult result = new NtFileResult(this))
                {
                    NtStatus status = result.CompleteCall(NtSystemCalls.NtQueryDirectoryFile(Handle, result.EventHandle,
                        IntPtr.Zero, IntPtr.Zero, result.IoStatusBuffer, buffer, buffer.Length, FileInformationClass.FileDirectoryInformation, false, mask, true));

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

                    if (status != NtStatus.STATUS_NO_MORE_FILES)
                    {
                        status.ToNtException();
                    }
                }
            }
        }

        private byte[] Read(int length, LargeInteger position)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(length))
            {
                using (NtFileResult result = new NtFileResult(this))
                {
                    NtStatus status = result.CompleteCall(NtSystemCalls.NtReadFile(Handle, result.EventHandle, IntPtr.Zero,
                        IntPtr.Zero, result.IoStatusBuffer, buffer, buffer.Length, position, IntPtr.Zero)).ToNtException();

                    return buffer.ReadBytes(result.Information32);
                }
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
            return Read(length, new LargeInteger(position));
        }

        /// <summary>
        /// Read data from a file with a length.
        /// </summary>
        /// <param name="length">The length of the read</param>
        /// <returns>The read bytes, this can be smaller than length.</returns>
        public byte[] Read(int length)
        {
            return Read(length, null);
        }

        private async Task<byte[]> ReadAsync(int length, LargeInteger position, CancellationToken token)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(length))
            {
                IoStatus io_status = await RunFileCallAsync(result => NtSystemCalls.NtReadFile(Handle, result.EventHandle, IntPtr.Zero,
                            IntPtr.Zero, result.IoStatusBuffer, buffer, buffer.Length, position, IntPtr.Zero), token);
                return buffer.ReadBytes(io_status.Information32);
            }
        }

        /// <summary>
        /// Read data from a file with a length and position.
        /// </summary>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <returns>The read bytes, this can be smaller than length.</returns>
        public Task<byte[]> ReadAsync(int length, long position, CancellationToken token)
        {
            return ReadAsync(length, new LargeInteger(position), token);
        }

        /// <summary>
        /// Read data from a file with a length and position.
        /// </summary>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read</param>
        /// <returns>The read bytes, this can be smaller than length.</returns>
        public Task<byte[]> ReadAsync(int length, long position)
        {
            return ReadAsync(length, position, CancellationToken.None);
        }

        private int Write(byte[] data, LargeInteger position)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(data))
            {
                using (NtFileResult result = new NtFileResult(this))
                {
                    NtStatus status = result.CompleteCall(NtSystemCalls.NtWriteFile(Handle, result.EventHandle, IntPtr.Zero,
                        IntPtr.Zero, result.IoStatusBuffer, buffer, buffer.Length, position, IntPtr.Zero)).ToNtException();

                    return result.Information32;
                }
            }
        }

        private async Task<IoStatus> RunFileCallAsync(Func<NtFileResult, NtStatus> func, CancellationToken token)
        {
            using (var linked_cts = CancellationTokenSource.CreateLinkedTokenSource(token, _cts.Token))
            {
                using (NtFileResult result = new NtFileResult(this))
                {
                    NtStatus status = await result.CompleteCallAsync(func(result), linked_cts.Token);
                    if (status == NtStatus.STATUS_PENDING)
                    {
                        result.Cancel();
                        throw new NtException(NtStatus.STATUS_CANCELLED);
                    }
                    status.ToNtException();
                    return result.Result;
                }
            }
        }

        private async Task<int> WriteAsync(byte[] data, LargeInteger position, CancellationToken token)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(data))
            {
                IoStatus io_status = await RunFileCallAsync(result => NtSystemCalls.NtWriteFile(Handle, result.EventHandle, IntPtr.Zero,
                            IntPtr.Zero, result.IoStatusBuffer, buffer, buffer.Length, position, IntPtr.Zero), token);
                return io_status.Information32;
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
            return Write(data, new LargeInteger(position));
        }

        /// <summary>
        /// Write data to a file
        /// </summary>
        /// <param name="data">The data to write</param>
        /// <returns>The number of bytes written</returns>
        public int Write(byte[] data)
        {
            return Write(data, null);
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
        /// <returns>The number of bytes written</returns>
        public Task<int> WriteAsync(byte[] data, long position, CancellationToken token)
        {
            return WriteAsync(data, new LargeInteger(position), token);
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
            using (NtFileResult result = new NtFileResult(this))
            {
                result.CompleteCall(NtSystemCalls.NtLockFile(Handle, result.EventHandle, IntPtr.Zero,
                    IntPtr.Zero, result.IoStatusBuffer, new LargeInteger(offset), 
                    new LargeInteger(size), 0, fail_immediately, exclusive)).ToNtException();
            }
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
        public async Task LockAsync(long offset, long size, bool fail_immediately, bool exclusive, CancellationToken token)
        {
            await RunFileCallAsync(result => NtSystemCalls.NtLockFile(Handle, result.EventHandle, IntPtr.Zero,
                                                                     IntPtr.Zero, result.IoStatusBuffer, new LargeInteger(offset),
                                                                     new LargeInteger(size), 0, fail_immediately, exclusive), token);
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
        public void Unlock(long offset, long size)
        {
            IoStatus io_status = new IoStatus();
            NtSystemCalls.NtUnlockFile(Handle, io_status, 
                new LargeInteger(offset), new LargeInteger(size), 0).ToNtException();
        }

        /// <summary>
        /// Get or set the current file position.
        /// </summary>
        public long Position
        {
            get
            {
                return QueryFileFixed<FilePositionInformation>(FileInformationClass.FilePositionInformation).CurrentByteOffset.QuadPart;
            }

            set
            {
                var position = new FilePositionInformation();
                position.CurrentByteOffset.QuadPart = value;

                SetFileFixed(position, FileInformationClass.FilePositionInformation);
            }
        }

        /// <summary>
        /// Get or sets the file's length
        /// </summary>
        public long Length
        {
            get
            {
                return QueryFileFixed<FileStandardInformation>(FileInformationClass.FileStandardInformation).EndOfFile.QuadPart;
            }

            set
            {
                SetEndOfFile(value);
            }
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

        [Flags]
        enum FinalPathNameFlags
        {
            None = 0,
            NameGuid = 1,
            NameNt = 2,
            NameNone = 4,
            Opened = 8,
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetFinalPathNameByHandle(SafeKernelObjectHandle hFile, StringBuilder lpszFilePath,
            int cchFilePath, FinalPathNameFlags dwFlags);

        private string GetPathNameInternal(FinalPathNameFlags flags)
        {
            StringBuilder builder = new StringBuilder(1000);
            if (GetFinalPathNameByHandle(Handle, builder, builder.Capacity, flags) == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return builder.ToString();
        }

        /// <summary>
        /// Get the Win32 path name for the file.
        /// </summary>
        /// <returns>The path, String.Empty on error.</returns>
        public string Win32PathName
        {
            get
            {
                try
                {
                    string ret = GetPathNameInternal(FinalPathNameFlags.None);
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
                catch (Win32Exception)
                {
                    return String.Empty;
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

        private T QueryFileFixed<T>(FileInformationClass info_class) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                IoStatus status = new IoStatus();
                NtSystemCalls.NtQueryInformationFile(Handle, status, buffer,
                    buffer.Length, info_class).ToNtException();
                return buffer.Result;
            }
        }

        private void SetFileFixed<T>(T value, FileInformationClass info_class) where T : new()
        {
            using (var buffer = value.ToBuffer())
            {
                IoStatus io_status = new IoStatus();
                NtSystemCalls.NtSetInformationFile(Handle, io_status, 
                    buffer, buffer.Length, info_class).ToNtException();
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
        public uint Characteristics
        {
            get
            {
                return QueryVolumeFixed<FileFsDeviceInformation>(FsInformationClass.FileFsDeviceInformation).Characteristics;
            }
        }

        [DllImport("kernel32.dll")]
        private static extern int GetFileType(SafeKernelObjectHandle handle);

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
                return TryGetName(FileInformationClass.FileShortNameInformation);
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
        public Task RequestOplockAsync(OplockRequestLevel level, CancellationToken token)
        {
            return FsControlAsync(GetOplockFsctl(level), null, null, token);
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
            while(true)
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

            SetFileFixed(info, FileInformationClass.FileCompletionInformation);
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
        /// Set the cached signing level for a file.
        /// </summary>
        /// <param name="flags">Flags to set for the cache.</param>
        /// <param name="signing_level">The signing level to cache</param>
        /// <param name="name">Optional name for the cache.</param>
        public void SetCachedSigningLevel(int flags, SigningLevel signing_level, string name)
        {
            NtSecurity.SetCachedSigningLevel(Handle, flags, signing_level, new SafeKernelObjectHandle[] { Handle }, name);
        }

        /// <summary>
        /// Set the end of file.
        /// </summary>
        /// <param name="offset">The offset to the end of file.</param>
        public void SetEndOfFile(long offset)
        {
            FileEndOfFileInformation eof = new FileEndOfFileInformation();
            eof.EndOfFile.QuadPart = offset;
            SetFileFixed(eof, FileInformationClass.FileEndOfFileInformation);
        }

        /// <summary>
        /// Set the valid data length of the file without zeroing. Needs SeManageVolumePrivilege.
        /// </summary>
        /// <param name="length">The length to set.</param>
        public void SetValidDataLength(long length)
        {
            FileValidDataLengthInformation data_length = new FileValidDataLengthInformation();
            data_length.ValidDataLength.QuadPart = length;
            SetFileFixed(data_length, FileInformationClass.FileValidDataLengthInformation);
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

                    int ofs = 0;                    
                    while (!done)
                    {
                        var stream = buffer.GetStructAtOffset<FileStreamInformation>(ofs);
                        yield return new FileStreamEntry(stream);
                        var result = stream.Result;
                        ofs += result.NextEntryOffset;
                        done = result.NextEntryOffset == 0;
                    }
                }
            }
        }

        /// <summary>
        /// Get the file mode.
        /// </summary>
        public FileOpenOptions Mode
        {
            get
            {
                return (FileOpenOptions)QueryFileFixed<int>(FileInformationClass.FileModeInformation);
            }
        }

        /// <summary>
        /// Get file access information.
        /// </summary>
        public AccessMask Access
        {
            get
            {
                return QueryFileFixed<AccessMask>(FileInformationClass.FileAccessInformation);
            }
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
        /// Gets whether the file is on a remote file system.
        /// </summary>
        public bool IsRemote
        {
            get
            {
                return QueryFileFixed<bool>(FileInformationClass.FileIsRemoteDeviceInformation);
            }
        }
    }

    /// <summary>
    /// Utility functions for files
    /// </summary>
    public static class NtFileUtils
    {
        /// <summary>
        /// Convert a DOS filename to an absolute NT filename
        /// </summary>
        /// <param name="filename">The filename, can be relative</param>
        /// <returns>The NT filename</returns>
        public static string DosFileNameToNt(string filename)
        {
            UnicodeStringOut nt_name = new UnicodeStringOut();
            try
            {
                IntPtr short_path;
                NtRtl.RtlDosPathNameToRelativeNtPathName_U_WithStatus(filename, out nt_name, out short_path, null).ToNtException();
                return nt_name.ToString();
            }
            finally
            {
                if (nt_name.Buffer != IntPtr.Zero)
                {
                    NtRtl.RtlFreeUnicodeString(ref nt_name);
                }
            }
        }

        /// <summary>
        /// Convert a DOS filename to an NT filename and get as an ObjectAttributes structure
        /// </summary>
        /// <param name="filename">The filename</param>
        /// <returns>The object attributes</returns>
        public static ObjectAttributes DosFileNameToObjectAttributes(string filename)
        {
            UnicodeStringOut nt_name = new UnicodeStringOut();
            RtlRelativeName relative_name = new RtlRelativeName();
            try
            {
                IntPtr short_path;
                NtRtl.RtlDosPathNameToRelativeNtPathName_U_WithStatus(filename, out nt_name, out short_path, relative_name).ToNtException();
                if (relative_name.RelativeName.Buffer != IntPtr.Zero)
                {
                    return new ObjectAttributes(relative_name.RelativeName.ToString(), AttributeFlags.CaseInsensitive,
                        new SafeKernelObjectHandle(relative_name.ContainingDirectory, false), null, null);
                }
                else
                {
                    return new ObjectAttributes(nt_name.ToString(), AttributeFlags.CaseInsensitive);
                }
            }
            finally
            {
                if (nt_name.Buffer != IntPtr.Zero)
                {
                    NtRtl.RtlFreeUnicodeString(ref nt_name);
                }

                if (relative_name.RelativeName.Buffer != IntPtr.Zero)
                {
                    NtRtl.RtlReleaseRelativeName(relative_name);
                }
            }
        }

        /// <summary>
        /// Convert a DOS filename to a UNICODE_STRING structure
        /// </summary>
        /// <param name="filename">The DOS filename</param>
        /// <returns>The UNICODE_STRING</returns>
        public static UnicodeString DosFileNameToUnicodeString(string filename)
        {
            return new UnicodeString(DosFileNameToNt(filename));
        }

        /// <summary>
        /// Get type of DOS path
        /// </summary>
        /// <param name="filename">The DOS filename</param>
        /// <returns>The type of DOS path</returns>
        public static RtlPathType GetDosPathType(string filename)
        {
            return NtRtl.RtlDetermineDosPathNameType_U(filename);
        }

        /// <summary>
        /// Map directory access rights to file access rights.
        /// </summary>
        /// <param name="access_rights">The directory access rights to map.</param>
        /// <returns>The mapped access rights.</returns>
        public static FileAccessRights MapToFileAccess(this FileDirectoryAccessRights access_rights)
        {
            return (FileAccessRights)(uint)access_rights;
        }

        /// <summary>
        /// Convert a file ID long to a string.
        /// </summary>
        /// <param name="fileid">The file ID to convert</param>
        /// <returns>The string format of the file id.</returns>
        public static string FileIdToString(long fileid)
        {
            return Encoding.Unicode.GetString(BitConverter.GetBytes(fileid));
        }
    }
}
