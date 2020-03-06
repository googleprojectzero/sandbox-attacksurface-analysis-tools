//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.IO;
using System.Runtime.InteropServices;

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
        public static extern NtStatus NtReadFileScatter(
          SafeKernelObjectHandle FileHandle,
          SafeKernelObjectHandle Event,
          IntPtr ApcRoutine,
          IntPtr ApcContext,
          SafeIoStatusBuffer IoStatusBlock,
          [MarshalAs(UnmanagedType.LPArray), In] FileSegmentElement[] SegmentArray,
          int Length,
          [In] LargeInteger ByteOffset,
          IntPtr Key);

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
        public static extern NtStatus NtWriteFileGather(
            SafeKernelObjectHandle FileHandle,
            SafeKernelObjectHandle Event,
            IntPtr ApcRoutine,
            IntPtr ApcContext,
            SafeIoStatusBuffer IoStatusBlock,
            [MarshalAs(UnmanagedType.LPArray), In] FileSegmentElement[] SegmentArray,
            int Length,
            [In] LargeInteger ByteOffset,
            IntPtr Key);

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

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCancelSynchronousIoFile(SafeKernelObjectHandle ThreadHandle, 
            [In] SafeIoStatusBuffer IoRequestToCancel, [Out] IoStatus IoStatusBlock);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtNotifyChangeDirectoryFile(
            SafeKernelObjectHandle FileHandle,
            SafeKernelObjectHandle Event,
            IntPtr ApcRoutine,
            IntPtr ApcContext,
            SafeIoStatusBuffer IoStatusBlock,
            SafeBuffer Buffer,
            int BufferSize,
            DirectoryChangeNotifyFilter CompletionFilter,
            bool WatchTree
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtNotifyChangeDirectoryFileEx(
            SafeKernelObjectHandle FileHandle,
            SafeKernelObjectHandle Event,
            IntPtr ApcRoutine,
            IntPtr ApcContext,
            SafeIoStatusBuffer IoStatusBlock,
            SafeBuffer Buffer,
            int BufferSize,
            DirectoryChangeNotifyFilter CompletionFilter,
            bool WatchTree,
            DirectoryNotifyInformationClass DirectoryNotifyInformationClass
        );
    }

    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlWow64EnableFsRedirection(bool Wow64FsEnableRedirection);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlWow64EnableFsRedirectionEx(IntPtr DisableFsRedirection,
            out IntPtr OldFsRedirectionLevel);
    }

    [StructLayout(LayoutKind.Sequential, Size = 8)]
    public struct FileSegmentElement
    {
        public IntPtr Buffer;
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

    public enum NamedPipeConfiguration
    {
        Inbound = 0,
        Outbound = 1,
        FullDuplex = 2,
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
        public static extern NtStatus RtlDefaultNpAcl(out SafeProcessHeapBuffer NamedPipeAcl);
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
    public struct FileDispositionInformation
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
        IgnoreReadOnlyAttribute = 0x00000010,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileDispositionInformationEx
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
        SupressStorageReserveInheritance = 0x00000008,
        NoIncreaseAvailableSpace = 0x00000010,
        NoDecreaseAvailableSpace = 0x00000020,
        IgnoreReadOnlyAttribute = 0x00000040,
        ForceResizeTargetSR = 0x00000080,
        ForceResourceSourceSR = 0x00000100,
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

    [StructLayout(LayoutKind.Sequential)]
    public struct FileCompletionInformation
    {
        public IntPtr CompletionPort;
        public IntPtr Key;
    }

    [Flags]
    public enum FileRemoteProtocolFlags
    {
        None = 0,
        Loopback = 1,
        Offline = 2,
        PersistentHandle = 4,
        Privacy = 8,
        Integrity = 0x10,
        MutualAuth = 0x20,
    }

    [Flags]
    public enum FileRemoteProtocolShareFlags
    {
        None = 0,
        Unknown01 = 0x00000001,
        TimeWarp = 0x00000002,
        Unknown04 = 0x00000004,
        DFS = 0x00000008,
        ContinuousAvailability = 0x00000010,
        Scaleout = 0x00000020,
        Cluster = 0x00000040,
        Encrypted = 0x00000080,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileRemoteProtocolSpecificInformationServer
    {
        public FileRemoteProtocolShareFlags Capabilities;
    }

    [Flags]
    public enum FileRemoteProtocolServerFlags
    {
        DFS = 0x00000001,
        Leasing = 0x00000002,
        LargeMTU = 0x00000004,
        MultiChannel = 0x00000008,
        PersistentHandles = 0x00000010,
        DirectoryLeasing = 0x00000020,
        EncryptionAware = 0x00000040,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileRemoteProtocolSpecificInformationSmb2
    {
        public FileRemoteProtocolServerFlags Capabilities;
        public int CachingFlags;
        public byte ShareType;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x40)]
    public struct FileRemoteProtocolSpecificInformation
    {
        [FieldOffset(0)]
        public FileRemoteProtocolSpecificInformationServer Server;
        [FieldOffset(0)]
        public FileRemoteProtocolSpecificInformationSmb2 Smb2;
    }

    public enum FileRemoteProtocolType
    {
        MSNET = 0x00010000,
        SMB = 0x00020000,
        LANMAN = 0x00020000,
        NETWARE = 0x00030000,
        VINES = 0x00040000,
        TEN_NET = 0x00050000,
        LOCUS = 0x00060000,
        SUN_PC_NFS = 0x00070000,
        LANSTEP = 0x00080000,
        NINE_TILES = 0x00090000,
        LANTASTIC = 0x000A0000,
        AS400 = 0x000B0000,
        FTP_NFS = 0x000C0000,
        PATHWORKS = 0x000D0000,
        LIFENET = 0x000E0000,
        POWERLAN = 0x000F0000,
        BWNFS = 0x00100000,
        COGENT = 0x00110000,
        FARALLON = 0x00120000,
        APPLETALK = 0x00130000,
        INTERGRAPH = 0x00140000,
        SYMFONET = 0x00150000,
        CLEARCASE = 0x00160000,
        FRONTIER = 0x00170000,
        BMC = 0x00180000,
        DCE = 0x00190000,
        AVID = 0x001A0000,
        DOCUSPACE = 0x001B0000,
        MANGOSOFT = 0x001C0000,
        SERNET = 0x001D0000,
        RIVERFRONT1 = 0x001E0000,
        RIVERFRONT2 = 0x001F0000,
        DECORB = 0x00200000,
        PROTSTOR = 0x00210000,
        FJ_REDIR = 0x00220000,
        DISTINCT = 0x00230000,
        TWINS = 0x00240000,
        RDR2SAMPLE = 0x00250000,
        CSC = 0x00260000,
        THREE_IN_ONE = 0x00270000,
        EXTENDNET = 0x00290000,
        STAC = 0x002A0000,
        FOXBAT = 0x002B0000,
        YAHOO = 0x002C0000,
        EXIFS = 0x002D0000,
        DAV = 0x002E0000,
        KNOWARE = 0x002F0000,
        OBJECT_DIRE = 0x00300000,
        MASFAX = 0x00310000,
        HOB_NFS = 0x00320000,
        SHIVA = 0x00330000,
        IBMAL = 0x00340000,
        LOCK = 0x00350000,
        TERMSRV = 0x00360000,
        SRT = 0x00370000,
        QUINCY = 0x00380000,
        OPENAFS = 0x00390000,
        AVID1 = 0x003A0000,
        DFS = 0x003B0000,
        KWNP = 0x003C0000,
        ZENWORKS = 0x003D0000,
        DRIVEONWEB = 0x003E0000,
        VMWARE = 0x003F0000,
        RSFX = 0x00400000,
        MFILES = 0x00410000,
        MS_NFS = 0x00420000,
        GOOGLE = 0x00430000,
        NDFS = 0x00440000,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileRemoteProtocolInformation
    {
        public ushort StructureVersion;
        public ushort StructureSize;
        public FileRemoteProtocolType Protocol;
        public ushort ProtocolMajorVersion;
        public ushort ProtocolMinorVersion;
        public ushort ProtocolRevision;
        public ushort Reserved;
        public FileRemoteProtocolFlags Flags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public int[] GenericReserved;
        public FileRemoteProtocolSpecificInformation ProtocolSpecific;
    }

    public class FileRemoteProtocol
    {
        public FileRemoteProtocolType Protocol { get; }
        public Version ProtocolVersion { get; }
        public FileRemoteProtocolFlags Flags { get; }
        public FileRemoteProtocolSpecificInformation ProtocolSepecific { get; }

        internal FileRemoteProtocol(FileRemoteProtocolInformation info)
        {
            Protocol = info.Protocol;
            ProtocolVersion = new Version(info.ProtocolMajorVersion, info.ProtocolMinorVersion, info.ProtocolRevision);
            Flags = info.Flags;
            ProtocolSepecific = info.ProtocolSpecific;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FilePipeInformation
    {
        public NamedPipeReadMode ReadMode;
        public NamedPipeCompletionMode CompletionMode;
    }

    public enum NamedPipeState
    {
        Disconencted = 1,
        Listening = 2,
        Connected = 3,
        Closing = 4,
    }

    public enum NamedPipeEnd
    {
        Client = 0,
        Server = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FilePipeLocalInformation
    {
        public NamedPipeType NamedPipeType;
        public NamedPipeConfiguration NamedPipeConfiguration;
        public int MaximumInstances;
        public int CurrentInstances;
        public int InboundQuota;
        public int ReadDataAvailable;
        public int OutboundQuota;
        public int WriteQuotaAvailable;
        public NamedPipeState NamedPipeState;
        public NamedPipeEnd NamedPipeEnd;
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
        FileCaseSensitiveInformationForceAccessCheck
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
        FileFsSectorSizeInformation = 11,
        FileFsDataCopyInformation = 12,
        FileFsMetadataSizeInformation = 13,
        FileFsFullSizeInformationEx = 14
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
        Csv = 0x00010000,
        AllowAppContainerTraversal = 0x00020000,
        PortableDevice = 0x0040000
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
        public int FileIndex { get; }
        public DateTime CreationTime { get; }
        public DateTime LastAccessTime { get; }
        public DateTime LastWriteTime { get; }
        public DateTime ChangeTime { get; }
        public long EndOfFile { get; }
        public long AllocationSize { get; }
        public FileAttributes Attributes { get; }
        public string FileName { get; }

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
        public long Size { get; }
        public long AllocationSize { get; }
        public string Name { get; }

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
        Filter,
    }

    public enum OplockResponseLevel
    {
        BrokenToLevel2 = 0x7,
        BrokenToNone = 0x8,
    }

    public enum OplockAcknowledgeLevel
    {
        Acknowledge,
        ClosePending,
        No2
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

    public enum StorageReserveId
    {
        None,
        Hard,
        Soft
    }

    public struct FileStorageReserveIdInformation
    {
        public StorageReserveId StorageReserveId;
    }

    [Flags]
    public enum FileCaseSensitiveFlags
    {
        None = 0,
        CaseSensitiveDir = 1,
    }

    public struct FileCaseSensitiveInformation
    {
        public FileCaseSensitiveFlags Flags;
    }


    [Flags]
    public enum DirectoryChangeNotifyFilter
    {
        None = 0,
        FileName = 0x00000001,
        DirName = 0x00000002,
        Attributes = 0x00000004,
        Size = 0x00000008,
        LastWrite = 0x00000010,
        LastAccess = 0x00000020,
        Creation = 0x00000040,
        Ea = 0x00000080,
        Security = 0x00000100,
        StreamName = 0x00000200,
        StreamSize = 0x00000400,
        StreamWrite = 0x00000800,
        All = 0x00000FFF
    }

    public enum FileNotificationAction
    {
        Added = 1,
        Removed = 2,
        Modified = 3,
        RenamedOldName = 4,
        RenamedNewName = 5,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("FileName")]
    public struct FileNotifyInformation
    {
        public int NextEntryOffset;
        public FileNotificationAction Action;
        public int FileNameLength;
        public char FileName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("FileName")]
    public struct FileNotifyExtendedInformation
    {
        public int NextEntryOffset;
        public FileNotificationAction Action;
        public LargeIntegerStruct CreationTime;
        public LargeIntegerStruct LastModificationTime;
        public LargeIntegerStruct LastChangeTime;
        public LargeIntegerStruct LastAccessTime;
        public LargeIntegerStruct AllocatedLength;
        public LargeIntegerStruct FileSize;
        public FileAttributes FileAttributes;
        public int ReparsePointTag;
        public LargeIntegerStruct FileId;
        public LargeIntegerStruct ParentFileId;
        public int FileNameLength;
        public char FileName;
    }

    public sealed class DirectoryChangeNotification
    {
        public FileNotificationAction Action { get; }
        public string FileName { get; }
        public string FullPath { get; }

        internal DirectoryChangeNotification(string base_path, SafeStructureInOutBuffer<FileNotifyInformation> buffer)
        {
            var info = buffer.Result;
            Action = info.Action;
            FileName = buffer.Data.ReadUnicodeString(info.FileNameLength / 2);
            FullPath = Path.Combine(base_path, FileName);
        }
    }

    public sealed class DirectoryChangeNotificationExtended
    {
        public FileNotificationAction Action { get; }
        public string FileName { get; }
        public string FullPath { get; }
        public DateTime CreationTime { get; }
        public DateTime LastModificationTime { get; }
        public DateTime LastChangeTime { get; }
        public DateTime LastAccessTime { get; }
        public long AllocatedLength { get; }
        public long FileSize { get; }
        public FileAttributes FileAttributes { get; }
        public ReparseTag ReparsePointTag { get; }
        public long FileId { get; }
        public long ParentFileId { get; }

        internal DirectoryChangeNotificationExtended(string base_path, SafeStructureInOutBuffer<FileNotifyExtendedInformation> buffer)
        {
            var info = buffer.Result;
            Action = info.Action;
            CreationTime = info.CreationTime.ToDateTime();
            LastModificationTime = info.LastModificationTime.ToDateTime();
            LastChangeTime = info.LastChangeTime.ToDateTime();
            LastAccessTime = info.LastAccessTime.ToDateTime();
            AllocatedLength = info.AllocatedLength.QuadPart;
            FileSize = info.FileSize.QuadPart;
            FileAttributes = info.FileAttributes;
            ReparsePointTag = (ReparseTag)info.ReparsePointTag;
            FileId = info.FileId.QuadPart;
            ParentFileId = info.ParentFileId.QuadPart;
            FileName = buffer.Data.ReadUnicodeString(info.FileNameLength / 2);
            FullPath = Path.Combine(base_path, FileName);
        }
    }

    public enum DirectoryNotifyInformationClass
    {
        DirectoryNotifyInformation = 1,
        DirectoryNotifyExtendedInformation = 2
    }

#pragma warning restore 1591
}
