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

using NtApiDotNet.Utilities.Reflection;
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
        public static extern NtStatus NtSetVolumeInformationFile(
            SafeKernelObjectHandle FileHandle,
            [Out] IoStatus IoStatusBlock,
            SafeBuffer FsInformation,
            int Length,
            FsInformationClass FsInformationClass
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
          [MarshalAs(UnmanagedType.U1)]
          bool FailImmediately,
          [MarshalAs(UnmanagedType.U1)]
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
          [MarshalAs(UnmanagedType.U1)]
          bool ReturnSingleEntry,
          SafeBuffer EaList,
          int EaListLength,
          [In] OptionalInt32 EaIndex,
          [MarshalAs(UnmanagedType.U1)]
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
            [MarshalAs(UnmanagedType.U1)] bool WatchTree
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
            [MarshalAs(UnmanagedType.U1)] bool WatchTree,
            DirectoryNotifyInformationClass DirectoryNotifyInformationClass
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetQuotaInformationFile(
          SafeKernelObjectHandle FileHandle,
          IoStatus IoStatusBlock,
          SafeBuffer Buffer,
          int Length
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryQuotaInformationFile(
          SafeKernelObjectHandle FileHandle,
          [In, Out] IoStatus IoStatusBlock,
          SafeBuffer Buffer,
          int Length,
          [MarshalAs(UnmanagedType.U1)]
          bool ReturnSingleEntry,
          SafeBuffer SidList,
          int SidListLength,
          SafeSidBufferHandle StartSid,
          [MarshalAs(UnmanagedType.U1)]
          bool RestartScan
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryAttributesFile(
          [In] ObjectAttributes ObjectAttributes,
          out FileBasicInformation FileInformation
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryFullAttributesFile(
            [In] ObjectAttributes ObjectAttributes,
            out FileNetworkOpenInformation FileInformation
        );
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct GenerateNameContext
    {
        public ushort Checksum;
        [MarshalAs(UnmanagedType.U1)]
        public bool CheckSumInserted;
        public byte NameLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] NameBuffer;
        public int ExtensionLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] ExtensionBuffer;
        public int LastIndexValue;
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

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlWow64EnableFsRedirection(bool Wow64FsEnableRedirection);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlWow64EnableFsRedirectionEx(IntPtr DisableFsRedirection,
            out IntPtr OldFsRedirectionLevel);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlGenerate8dot3Name(
          [In] UnicodeString Name,
          [MarshalAs(UnmanagedType.U1)] bool AllowExtendedCharacters,
          ref GenerateNameContext Context,
          [In, Out] UnicodeStringAllocated Name8dot3
        );

        [DllImport("ntdll.dll")]
        [return: MarshalAs(UnmanagedType.U1)]
        public static extern bool RtlIsNameLegalDOS8Dot3(
            UnicodeString Name,
            AnsiString OemName,
            out bool NameContainsSpaces
        );
    }

    public enum FileDisposition
    {
        [SDKName("FILE_SUPERSEDE")]
        Supersede = 0x00000000,
        [SDKName("FILE_OPEN")]
        Open = 0x00000001,
        [SDKName("FILE_CREATE")]
        Create = 0x00000002,
        [SDKName("FILE_OPEN_IF")]
        OpenIf = 0x00000003,
        [SDKName("FILE_OVERWRITE")]
        Overwrite = 0x00000004,
        [SDKName("FILE_OVERWRITE_IF")]
        OverwriteIf = 0x00000005,
    }

    public enum FileOpenResult
    {
        [SDKName("FILE_SUPERSEDED")]
        Superseded = 0x00000000,
        [SDKName("FILE_OPENED")]
        Opened = 0x00000001,
        [SDKName("FILE_CREATED")]
        Created = 0x00000002,
        [SDKName("FILE_OVERWRITTEN")]
        Overwritten = 0x00000003,
        [SDKName("FILE_EXISTS")]
        Exists = 0x00000004,
        [SDKName("FILE_DOES_NOT_EXIST")]
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

        internal DateTime ToDateTime()
        {
            long time = DateTimeHigh;
            time <<= 32;
            time |= DateTimeLow;
            try
            {
                return DateTime.FromFileTime(time);
            }
            catch (ArgumentException)
            {
                return DateTime.MinValue;
            }
        }
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
        ForceResizeSourceSR = 0x00000100,
        ForceResizeSR = ForceResizeTargetSR | ForceResizeSourceSR
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

    [StructLayout(LayoutKind.Sequential)]
    public struct FileNetworkOpenInformation
    {
        public LargeIntegerStruct CreationTime;
        public LargeIntegerStruct LastAccessTime;
        public LargeIntegerStruct LastWriteTime;
        public LargeIntegerStruct ChangeTime;
        public LargeIntegerStruct AllocationSize;
        public LargeIntegerStruct EndOfFile;
        public FileAttributes FileAttributes;
    }

    public interface IFileDirectoryInformation<T, U> where T : struct where U : FileDirectoryEntry
    {
        int GetNextOffset();
        U ToEntry(SafeStructureInOutBuffer<T> buffer);
        FileAttributes GetAttributes();
    }

    [StructLayout(LayoutKind.Sequential), DataStart("FileName")]
    public struct FileDirectoryInformation : IFileDirectoryInformation<FileDirectoryInformation, FileDirectoryEntry>
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

        int IFileDirectoryInformation<FileDirectoryInformation, FileDirectoryEntry>.GetNextOffset()
        {
            return NextEntryOffset;
        }

        FileAttributes IFileDirectoryInformation<FileDirectoryInformation, FileDirectoryEntry>.GetAttributes()
        {
            return FileAttributes;
        }

        FileDirectoryEntry IFileDirectoryInformation<FileDirectoryInformation, FileDirectoryEntry>.ToEntry(SafeStructureInOutBuffer<FileDirectoryInformation> buffer)
        {
            string file_name = buffer.Data.ReadUnicodeString(FileNameLength / 2);
            return new FileDirectoryEntry(this, file_name);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("FileName")]
    public struct FileBothDirectoryInformation : IFileDirectoryInformation<FileBothDirectoryInformation, FileBothDirectoryEntry>
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
        public int EaSize;
        public byte ShortNameLength;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 12)]
        public string ShortName;
        public ushort FileName; // String

        int IFileDirectoryInformation<FileBothDirectoryInformation, FileBothDirectoryEntry>.GetNextOffset()
        {
            return NextEntryOffset;
        }

        FileAttributes IFileDirectoryInformation<FileBothDirectoryInformation, FileBothDirectoryEntry>.GetAttributes()
        {
            return FileAttributes;
        }

        FileBothDirectoryEntry IFileDirectoryInformation<FileBothDirectoryInformation, FileBothDirectoryEntry>.ToEntry(SafeStructureInOutBuffer<FileBothDirectoryInformation> buffer)
        {
            string file_name = buffer.Data.ReadUnicodeString(FileNameLength / 2);
            return new FileBothDirectoryEntry(this, file_name);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("FileName")]
    public struct FileIdBothDirectoryInformation : IFileDirectoryInformation<FileIdBothDirectoryInformation, FileIdBothDirectoryEntry>
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
        public int EaSize;
        public byte ShortNameLength;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 12)]
        public string ShortName;
        public LargeIntegerStruct FileId;
        public ushort FileName; // String

        int IFileDirectoryInformation<FileIdBothDirectoryInformation, FileIdBothDirectoryEntry>.GetNextOffset()
        {
            return NextEntryOffset;
        }

        FileAttributes IFileDirectoryInformation<FileIdBothDirectoryInformation, FileIdBothDirectoryEntry>.GetAttributes()
        {
            return FileAttributes;
        }

        FileIdBothDirectoryEntry IFileDirectoryInformation<FileIdBothDirectoryInformation, FileIdBothDirectoryEntry>.ToEntry(SafeStructureInOutBuffer<FileIdBothDirectoryInformation> buffer)
        {
            string file_name = buffer.Data.ReadUnicodeString(FileNameLength / 2);
            return new FileIdBothDirectoryEntry(this, file_name);
        }
    }

    [StructLayout(LayoutKind.Sequential), DataStart("FileName")]
    public struct FileIdFullDirectoryInformation : IFileDirectoryInformation<FileIdFullDirectoryInformation, FileIdDirectoryEntry>
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
        public int EaSize;
        public LargeIntegerStruct FileId;
        public ushort FileName; // String

        int IFileDirectoryInformation<FileIdFullDirectoryInformation, FileIdDirectoryEntry>.GetNextOffset()
        {
            return NextEntryOffset;
        }

        FileAttributes IFileDirectoryInformation<FileIdFullDirectoryInformation, FileIdDirectoryEntry>.GetAttributes()
        {
            return FileAttributes;
        }

        FileIdDirectoryEntry IFileDirectoryInformation<FileIdFullDirectoryInformation, FileIdDirectoryEntry>.ToEntry(SafeStructureInOutBuffer<FileIdFullDirectoryInformation> buffer)
        {
            string file_name = buffer.Data.ReadUnicodeString(FileNameLength / 2);
            return new FileIdDirectoryEntry(this, file_name);
        }
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

    [StructLayout(LayoutKind.Sequential)]
    public struct FilePipeRemoteInformation
    {
        public LargeIntegerStruct CollectDataTime;
        public int MaximumCollectionCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileMailslotQueryInformation
    {
        public int MaximumMessageSize;
        public int MailslotQuota;
        public int NextMessageSize;
        public int MessagesAvailable;
        public LargeIntegerStruct ReadTimeout;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileMailslotSetInformation
    {
        public LargeIntegerStruct ReadTimeout;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileMailslotPeekBuffer
    {
        public int ReadDataAvailable;
        public int NumberOfMessages;
        public int MessageLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileObjectIdInformation
    {
        public long FileReference;
        public Guid ObjectId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48)]
        public byte[] ExtendedInfo;
        public Guid BirthVolumeId => new Guid(ExtendedInfo.Slice(0, 16));
        public Guid BirthObjectId => new Guid(ExtendedInfo.Slice(16, 16));
        public Guid DomainId => new Guid(ExtendedInfo.Slice(32, 16));
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileObjectIdBuffer
    {
        public Guid ObjectId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48)]
        public byte[] ExtendedInfo;

        public Guid BirthVolumeId => new Guid(ExtendedInfo.Slice(0, 16));
        public Guid BirthObjectId => new Guid(ExtendedInfo.Slice(16, 16));
        public Guid DomainId => new Guid(ExtendedInfo.Slice(32, 16));
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileSetSparseBuffer
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool SetSparse;
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
        [SDKName("FILE_REMOVABLE_MEDIA")]
        RemovableMedia = 0x00000001,
        [SDKName("FILE_READ_ONLY_DEVICE")]
        ReadOnlyDevice = 0x00000002,
        [SDKName("FILE_FLOPPY_DISKETTE")]
        FloppyDiskette = 0x00000004,
        [SDKName("FILE_WRITE_ONCE_MEDIA")]
        WriteOnceMedia = 0x00000008,
        [SDKName("FILE_REMOTE_DEVICE")]
        RemoteDevice = 0x00000010,
        [SDKName("FILE_DEVICE_IS_MOUNTED")]
        DeviceIsMounted = 0x00000020,
        [SDKName("FILE_VIRTUAL_VOLUME")]
        VirtualVolume = 0x00000040,
        [SDKName("FILE_AUTOGENERATED_DEVICE_NAME")]
        AutoGeneratedName = 0x00000080,
        [SDKName("FILE_DEVICE_SECURE_OPEN")]
        SecureOpen = 0x00000100,
        [SDKName("FILE_CHARACTERISTIC_PNP_DEVICE")]
        PnpDevice = 0x00000800,
        [SDKName("FILE_CHARACTERISTIC_TS_DEVICE")]
        TsDevice = 0x00001000,
        [SDKName("FILE_CHARACTERISTIC_WEBDAV_DEVICE")]
        WebDavDevice = 0x00002000,
        [SDKName("FILE_CHARACTERISTIC_CSV")]
        Csv = 0x00010000,
        [SDKName("FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL")]
        AllowAppContainerTraversal = 0x00020000,
        [SDKName("FILE_PORTABLE_DEVICE")]
        PortableDevice = 0x0040000
    }

    [StructLayout(LayoutKind.Sequential)]
    public class FileFsDeviceInformation
    {
        public FileDeviceType DeviceType;
        public FileDeviceCharacteristics Characteristics;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("DriverName")]
    public struct FileFsDriverPathInformation
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool DriverInPath;
        public int DriverNameLength;
        public short DriverName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileFsVolumeFlagsInformation
    {
        public int Flags;
    }

    [Flags]
    public enum FileSystemControlFlags
    {
        QuotaNone = 0x00000000,
        QuoraTrack = 0x00000001,
        QuotaEnforce = 0x00000002,
        Unknown4 = 0x00000004,
        ContentIndexDisabled = 0x00000008,
        LogQuotaThreshold = 0x00000010,
        LogQuotaLimit = 0x00000020,
        LogVolumeThreshold = 0x00000040,
        LogVolumeLimit = 0x00000080,
        QuotasIncomplete = 0x00000100,
        QuotasRebuilding = 0x00000200
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileFsControlInformation
    {
        public LargeIntegerStruct FreeSpaceStartFiltering;
        public LargeIntegerStruct FreeSpaceThreshold;
        public LargeIntegerStruct FreeSpaceStopFiltering;
        public LargeIntegerStruct DefaultQuotaThreshold;
        public LargeIntegerStruct DefaultQuotaLimit;
        public FileSystemControlFlags FileSystemControlFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileFsDataCopyInformation
    {
        public int NumberOfCopies;
    }

    [Flags]
    public enum FileFsPersistentVolumeInformationFlags : uint
    {
        None = 0,
        ShortNameCreationDisabled = 0x00000001,
        VolumeScrubeDisabled = 0x00000002,
        GlobalMetadataNoSeekPenalty = 0x00000004,
        LocalMetadtaNoSeekPenalty = 0x00000008,
        NoHeatGathering = 0x00000010,
        ContainsBackingWIM = 0x00000020,
        BackedByWIM = 0x00000040,
        NoWriteAutoTiering = 0x00000080,
        TxFDisabled = 0x00000100,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileFsPersistentVolumeInformation
    {
        public FileFsPersistentVolumeInformationFlags VolumeFlags;
        public FileFsPersistentVolumeInformationFlags FlagMask;
        public int Version;
        public int Reserved;
    }

    [StructLayout(LayoutKind.Sequential), SDKName("IO_STATUS_BLOCK")]
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

    [StructLayout(LayoutKind.Sequential), SDKName("IO_STATUS_BLOCK")]
    public struct IoStatusStruct
    {
        public UIntPtr Pointer;
        public IntPtr Information;
    }

    [Flags]
    public enum FileShareMode
    {
        [SDKName("FILE_SHARE_NONE")]
        None = 0,
        [SDKName("FILE_SHARE_READ")]
        Read = 0x00000001,
        [SDKName("FILE_SHARE_WRITE")]
        Write = 0x00000002,
        [SDKName("FILE_SHARE_DELETE")]
        Delete = 0x00000004,
        All = Read | Write | Delete,
    }

    [Flags]
    public enum FileOpenOptions
    {
        None = 0,
        [SDKName("FILE_DIRECTORY_FILE")]
        DirectoryFile = 0x00000001,
        [SDKName("FILE_WRITE_THROUGH")]
        WriteThrough = 0x00000002,
        [SDKName("FILE_SEQUENTIAL_ONLY")]
        SequentialOnly = 0x00000004,
        [SDKName("FILE_NO_INTERMEDIATE_BUFFERING")]
        NoIntermediateBuffering = 0x00000008,
        [SDKName("FILE_SYNCHRONOUS_IO_ALERT")]
        SynchronousIoAlert = 0x00000010,
        [SDKName("FILE_SYNCHRONOUS_IO_NONALERT")]
        SynchronousIoNonAlert = 0x00000020,
        [SDKName("FILE_NON_DIRECTORY_FILE")]
        NonDirectoryFile = 0x00000040,
        [SDKName("FILE_CREATE_TREE_CONNECTION")]
        CreateTreeConnection = 0x00000080,
        [SDKName("FILE_COMPLETE_IF_OPLOCKED")]
        CompleteIfOplocked = 0x00000100,
        [SDKName("FILE_NO_EA_KNOWLEDGE")]
        NoEaKnowledge = 0x00000200,
        [SDKName("FILE_OPEN_REMOTE_INSTANCE")]
        OpenRemoteInstance = 0x00000400,
        [SDKName("FILE_RANDOM_ACCESS")]
        RandomAccess = 0x00000800,
        [SDKName("FILE_DELETE_ON_CLOSE")]
        DeleteOnClose = 0x00001000,
        [SDKName("FILE_OPEN_BY_FILE_ID")]
        OpenByFileId = 0x00002000,
        [SDKName("FILE_OPEN_FOR_BACKUP_INTENT")]
        OpenForBackupIntent = 0x00004000,
        [SDKName("FILE_NO_COMPRESSION")]
        NoCompression = 0x00008000,
        [SDKName("FILE_OPEN_REQUIRING_OPLOCK")]
        OpenRequiringOplock = 0x00010000,
        [SDKName("FILE_DISALLOW_EXCLUSIVE")]
        DisallowExclusive = 0x00020000,
        [SDKName("FILE_SESSION_AWARE")]
        SessionAware = 0x00040000,
        [SDKName("FILE_RESERVE_OPFILTER")]
        ReserveOpfilter = 0x00100000,
        [SDKName("FILE_OPEN_REPARSE_POINT")]
        OpenReparsePoint = 0x00200000,
        [SDKName("FILE_OPEN_NO_RECALL")]
        OpenNoRecall = 0x00400000,
        [SDKName("FILE_OPEN_FOR_FREE_SPACE_QUERY")]
        OpenForFreeSpaceQuery = 0x00800000
    }

    [Flags]
    public enum FileAccessRights : uint
    {
        None = 0,
        [SDKName("FILE_READ_DATA")]
        ReadData = 0x0001,
        [SDKName("FILE_WRITE_DATA")]
        WriteData = 0x0002,
        [SDKName("FILE_APPEND_DATA")]
        AppendData = 0x0004,
        [SDKName("FILE_READ_EA")]
        ReadEa = 0x0008,
        [SDKName("FILE_WRITE_EA")]
        WriteEa = 0x0010,
        [SDKName("FILE_EXECUTE")]
        Execute = 0x0020,
        [SDKName("FILE_DELETE_CHILD")]
        DeleteChild = 0x0040,
        [SDKName("FILE_READ_ATTRIBUTES")]
        ReadAttributes = 0x0080,
        [SDKName("FILE_WRITE_ATTRIBUTES")]
        WriteAttributes = 0x0100,
        [SDKName("GENERIC_READ")]
        GenericRead = GenericAccessRights.GenericRead,
        [SDKName("GENERIC_WRITE")]
        GenericWrite = GenericAccessRights.GenericWrite,
        [SDKName("GENERIC_EXECUTE")]
        GenericExecute = GenericAccessRights.GenericExecute,
        [SDKName("GENERIC_ALL")]
        GenericAll = GenericAccessRights.GenericAll,
        [SDKName("DELETE")]
        Delete = GenericAccessRights.Delete,
        [SDKName("READ_CONTROL")]
        ReadControl = GenericAccessRights.ReadControl,
        [SDKName("WRITE_DAC")]
        WriteDac = GenericAccessRights.WriteDac,
        [SDKName("WRITE_OWNER")]
        WriteOwner = GenericAccessRights.WriteOwner,
        [SDKName("SYNCHRONIZE")]
        Synchronize = GenericAccessRights.Synchronize,
        [SDKName("MAXIMUM_ALLOWED")]
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        [SDKName("ACCESS_SYSTEM_SECURITY")]
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    [Flags]
    public enum FileDirectoryAccessRights : uint
    {
        None = 0,
        [SDKName("FILE_LIST_DIRECTORY")]
        ListDirectory = 0x0001,
        [SDKName("FILE_ADD_FILE")]
        AddFile = 0x0002,
        [SDKName("FILE_ADD_SUBDIRECTORY")]
        AddSubDirectory = 0x0004,
        [SDKName("FILE_READ_EA")]
        ReadEa = 0x0008,
        [SDKName("FILE_WRITE_EA")]
        WriteEa = 0x0010,
        [SDKName("FILE_TRAVERSE")]
        Traverse = 0x0020,
        [SDKName("FILE_DELETE_CHILD")]
        DeleteChild = 0x0040,
        [SDKName("FILE_READ_ATTRIBUTES")]
        ReadAttributes = 0x0080,
        [SDKName("FILE_WRITE_ATTRIBUTES")]
        WriteAttributes = 0x0100,
        [SDKName("GENERIC_READ")]
        GenericRead = GenericAccessRights.GenericRead,
        [SDKName("GENERIC_WRITE")]
        GenericWrite = GenericAccessRights.GenericWrite,
        [SDKName("GENERIC_EXECUTE")]
        GenericExecute = GenericAccessRights.GenericExecute,
        [SDKName("GENERIC_ALL")]
        GenericAll = GenericAccessRights.GenericAll,
        [SDKName("DELETE")]
        Delete = GenericAccessRights.Delete,
        [SDKName("READ_CONTROL")]
        ReadControl = GenericAccessRights.ReadControl,
        [SDKName("WRITE_DAC")]
        WriteDac = GenericAccessRights.WriteDac,
        [SDKName("WRITE_OWNER")]
        WriteOwner = GenericAccessRights.WriteOwner,
        [SDKName("SYNCHRONIZE")]
        Synchronize = GenericAccessRights.Synchronize,
        [SDKName("MAXIMUM_ALLOWED")]
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        [SDKName("ACCESS_SYSTEM_SECURITY")]
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
        DirectoriesOnly = 2
    }

    [Flags]
    public enum DirectoryEntryIncludeFlags
    {
        Default = 0,
        FileId = 1,
        ShortName = 2,
        Placeholders = 4,
    }

    /// <summary>
    /// Class representing file information.
    /// </summary>
    public class FileInformation
    {
        /// <summary>
        /// Time of creation.
        /// </summary>
        public DateTime CreationTime { get; }
        /// <summary>
        /// Time of last access.
        /// </summary>
        public DateTime LastAccessTime { get; }
        /// <summary>
        /// Time of last write.
        /// </summary>
        public DateTime LastWriteTime { get; }
        /// <summary>
        /// Time of change.
        /// </summary>
        public DateTime ChangeTime { get; }
        /// <summary>
        /// Length of the file.
        /// </summary>
        public long EndOfFile { get; }
        /// <summary>
        /// Length of the file, alias of EndOfFile.
        /// </summary>
        public long FileSize => EndOfFile;
        /// <summary>
        /// Allocation size.
        /// </summary>
        public long AllocationSize { get; }
        /// <summary>
        /// File attributes.
        /// </summary>
        public FileAttributes Attributes { get; }

        /// <summary>
        /// Has the file got a set of attributes set.
        /// </summary>
        /// <param name="attributes">The attributes to check.</param>
        /// <returns>True if it has the attributes.</returns>
        public bool HasAttributes(FileAttributes attributes) => Attributes.HasFlagSet(attributes);

        /// <summary>
        /// Is the file a directory.
        /// </summary>
        public bool IsDirectory => HasAttributes(FileAttributes.Directory);

        /// <summary>
        /// Is the file a reparse point.
        /// </summary>
        public bool IsReparsePoint => HasAttributes(FileAttributes.ReparsePoint);

        internal FileInformation(FileDirectoryInformation dir_info)
        {
            CreationTime = dir_info.CreationTime.ToDateTime();
            LastAccessTime = dir_info.LastAccessTime.ToDateTime();
            LastWriteTime = dir_info.LastWriteTime.ToDateTime();
            ChangeTime = dir_info.ChangeTime.ToDateTime();
            EndOfFile = dir_info.EndOfFile.QuadPart;
            AllocationSize = dir_info.AllocationSize.QuadPart;
            Attributes = dir_info.FileAttributes;
        }

        internal FileInformation(FileIdFullDirectoryInformation dir_info)
        {
            CreationTime = dir_info.CreationTime.ToDateTime();
            LastAccessTime = dir_info.LastAccessTime.ToDateTime();
            LastWriteTime = dir_info.LastWriteTime.ToDateTime();
            ChangeTime = dir_info.ChangeTime.ToDateTime();
            EndOfFile = dir_info.EndOfFile.QuadPart;
            AllocationSize = dir_info.AllocationSize.QuadPart;
            Attributes = dir_info.FileAttributes;
        }

        internal FileInformation(FileBothDirectoryInformation dir_info)
        {
            CreationTime = dir_info.CreationTime.ToDateTime();
            LastAccessTime = dir_info.LastAccessTime.ToDateTime();
            LastWriteTime = dir_info.LastWriteTime.ToDateTime();
            ChangeTime = dir_info.ChangeTime.ToDateTime();
            EndOfFile = dir_info.EndOfFile.QuadPart;
            AllocationSize = dir_info.AllocationSize.QuadPart;
            Attributes = dir_info.FileAttributes;
        }

        internal FileInformation(FileIdBothDirectoryInformation dir_info)
        {
            CreationTime = dir_info.CreationTime.ToDateTime();
            LastAccessTime = dir_info.LastAccessTime.ToDateTime();
            LastWriteTime = dir_info.LastWriteTime.ToDateTime();
            ChangeTime = dir_info.ChangeTime.ToDateTime();
            EndOfFile = dir_info.EndOfFile.QuadPart;
            AllocationSize = dir_info.AllocationSize.QuadPart;
            Attributes = dir_info.FileAttributes;
        }

        internal FileInformation(FileNetworkOpenInformation open_info)
        {
            CreationTime = open_info.CreationTime.ToDateTime();
            LastAccessTime = open_info.LastAccessTime.ToDateTime();
            LastWriteTime = open_info.LastWriteTime.ToDateTime();
            ChangeTime = open_info.ChangeTime.ToDateTime();
            EndOfFile = open_info.EndOfFile.QuadPart;
            AllocationSize = open_info.AllocationSize.QuadPart;
            Attributes = open_info.FileAttributes;
        }
    }

    /// <summary>
    /// Class to represent a directory entry.
    /// </summary>
    public class FileDirectoryEntry : FileInformation
    {
        /// <summary>
        /// Index of the file.
        /// </summary>
        public int FileIndex { get; }
        /// <summary>
        /// File name.
        /// </summary>
        public string FileName { get; }

        internal FileDirectoryEntry(FileDirectoryInformation dir_info, string file_name)
            : base(dir_info)
        {
            FileIndex = dir_info.FileIndex;
            FileName = file_name;
        }

        internal FileDirectoryEntry(FileIdFullDirectoryInformation dir_info, string file_name)
            : base(dir_info)
        {
            FileIndex = dir_info.FileIndex;
            FileName = file_name;
        }

        internal FileDirectoryEntry(FileBothDirectoryInformation dir_info, string file_name)
            : base(dir_info)
        {
            FileIndex = dir_info.FileIndex;
            FileName = file_name;
        }

        internal FileDirectoryEntry(FileIdBothDirectoryInformation dir_info, string file_name)
            : base(dir_info)
        {
            FileIndex = dir_info.FileIndex;
            FileName = file_name;
        }
    }

    /// <summary>
    /// Class to represent a directory entry with file IDs.
    /// </summary>
    public class FileIdDirectoryEntry : FileDirectoryEntry
    {
        /// <summary>
        /// Length of any EA buffer.
        /// </summary>
        public int EaSize { get; }
        /// <summary>
        /// The file reference number if known.
        /// </summary>
        public long FileId { get; }

        internal FileIdDirectoryEntry(FileIdFullDirectoryInformation dir_info, string file_name)
            : base(dir_info, file_name)
        {
            EaSize = dir_info.EaSize;
            FileId = dir_info.FileId.QuadPart;
        }
    }

    /// <summary>
    /// Class to represent a directory entry with short names.
    /// </summary>
    public class FileBothDirectoryEntry : FileDirectoryEntry
    {
        /// <summary>
        /// Length of any EA buffer.
        /// </summary>
        public int EaSize { get; }
        /// <summary>
        /// The short name of the file.
        /// </summary>
        public string ShortName { get; }

        internal FileBothDirectoryEntry(FileBothDirectoryInformation dir_info, string file_name)
            : base(dir_info, file_name)
        {
            EaSize = dir_info.EaSize;
            ShortName = dir_info.ShortName.Substring(0, dir_info.ShortNameLength / 2);
        }
    }

    /// <summary>
    /// Class to represent a directory entry with short names and file ids.
    /// </summary>
    public class FileIdBothDirectoryEntry : FileDirectoryEntry
    {
        /// <summary>
        /// Length of any EA buffer.
        /// </summary>
        public int EaSize { get; }
        /// <summary>
        /// The short name of the file.
        /// </summary>
        public string ShortName { get; }
        /// <summary>
        /// The file reference number if known.
        /// </summary>
        public long FileId { get; }

        internal FileIdBothDirectoryEntry(FileIdBothDirectoryInformation dir_info, string file_name)
            : base(dir_info, file_name)
        {
            EaSize = dir_info.EaSize;
            ShortName = dir_info.ShortName.Substring(0, dir_info.ShortNameLength / 2);
            FileId = dir_info.FileId.QuadPart;
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
        public long ParentFileId { get; }
        public string FileName { get; }
        public string FullPath { get; }
        public string Win32Path { get; }

        internal FileLinkEntry(SafeStructureInOutBuffer<FileLinkEntryInformation> buffer, string parent_path, string win32_parent)
        {
            FileLinkEntryInformation entry = buffer.Result;
            ParentFileId = entry.ParentFileId;
            FileName = buffer.Data.ReadUnicodeString(entry.FileNameLength);
            FullPath = Path.Combine(parent_path, FileName);
            Win32Path = Path.Combine(win32_parent, FileName);
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

    [StructLayout(LayoutKind.Sequential)]
    public struct FileFsFullSizeInformation
    {
        public LargeIntegerStruct TotalAllocationUnits;
        public LargeIntegerStruct CallerAvailableAllocationUnits;
        public LargeIntegerStruct ActualAvailableAllocationUnits;
        public uint SectorsPerAllocationUnit;
        public uint BytesPerSector;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileFsFullSizeInformationEx
    {
        public ulong ActualTotalAllocationUnits;
        public ulong ActualAvailableAllocationUnits;
        public ulong ActualPoolUnavailableAllocationUnits;
        public ulong CallerTotalAllocationUnits;
        public ulong CallerAvailableAllocationUnits;
        public ulong CallerPoolUnavailableAllocationUnits;
        public ulong UsedAllocationUnits;
        public ulong TotalReservedAllocationUnits;
        public ulong VolumeStorageReserveAllocationUnits;
        public ulong AvailableCommittedAllocationUnits;
        public ulong PoolAvailableAllocationUnits;
        public uint SectorsPerAllocationUnit;
        public uint BytesPerSector;
    }

    public sealed class FileSystemVolumeInformation
    {
        public FileSystemAttributes Attributes { get; }
        public int MaximumComponentLength { get; }
        public string Name { get; }
        public DateTime CreationTime { get; }
        public uint SerialNumber { get; }
        public string Label { get; }
        public bool SupportsObjects { get; }
        public ulong ActualTotalAllocationUnits { get; }
        public ulong ActualAvailableAllocationUnits { get; }
        public ulong ActualPoolUnavailableAllocationUnits { get; }
        public ulong CallerTotalAllocationUnits { get; }
        public ulong CallerAvailableAllocationUnits { get; }
        public ulong CallerPoolUnavailableAllocationUnits { get; }
        public ulong UsedAllocationUnits { get; }
        public ulong TotalReservedAllocationUnits { get; }
        public ulong VolumeStorageReserveAllocationUnits { get; }
        public ulong AvailableCommittedAllocationUnits { get; }
        public ulong PoolAvailableAllocationUnits { get; }
        public uint SectorsPerAllocationUnit { get; }
        public uint BytesPerSector { get; }
        public ulong BytesPerAllocationUnit => SectorsPerAllocationUnit * BytesPerSector;
        public ulong TotalBytes => ActualTotalAllocationUnits * BytesPerAllocationUnit;
        public ulong AvailableBytes => ActualAvailableAllocationUnits * BytesPerAllocationUnit;
        public ulong CallerAvailableBytes => CallerAvailableAllocationUnits * BytesPerAllocationUnit;

        internal FileSystemVolumeInformation(SafeStructureInOutBuffer<FileFsAttributeInformation> attr_info,
            SafeStructureInOutBuffer<FileFsVolumeInformation> vol_info, FileFsFullSizeInformationEx file_size)
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

            ActualTotalAllocationUnits = file_size.ActualTotalAllocationUnits;
            ActualAvailableAllocationUnits = file_size.ActualAvailableAllocationUnits;
            ActualPoolUnavailableAllocationUnits = file_size.ActualPoolUnavailableAllocationUnits;
            CallerTotalAllocationUnits = file_size.CallerTotalAllocationUnits;
            CallerAvailableAllocationUnits = file_size.CallerAvailableAllocationUnits;
            CallerPoolUnavailableAllocationUnits = file_size.CallerPoolUnavailableAllocationUnits;
            UsedAllocationUnits = file_size.UsedAllocationUnits;
            TotalReservedAllocationUnits = file_size.TotalReservedAllocationUnits;
            VolumeStorageReserveAllocationUnits = file_size.VolumeStorageReserveAllocationUnits;
            AvailableCommittedAllocationUnits = file_size.AvailableCommittedAllocationUnits;
            PoolAvailableAllocationUnits = file_size.PoolAvailableAllocationUnits;
            SectorsPerAllocationUnit = file_size.SectorsPerAllocationUnit;
            BytesPerSector = file_size.BytesPerSector;
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

    internal interface IFileNotifyInformation
    {
        FileNotificationAction GetAction();
        int GetFileNameLength();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("FileName")]
    public struct FileNotifyInformation : IFileNotifyInformation
    {
        public int NextEntryOffset;
        public FileNotificationAction Action;
        public int FileNameLength;
        public char FileName;

        FileNotificationAction IFileNotifyInformation.GetAction()
        {
            return Action;
        }

        int IFileNotifyInformation.GetFileNameLength()
        {
            return FileNameLength;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("FileName")]
    public struct FileNotifyExtendedInformation : IFileNotifyInformation
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

        FileNotificationAction IFileNotifyInformation.GetAction()
        {
            return Action;
        }

        int IFileNotifyInformation.GetFileNameLength()
        {
            return FileNameLength;
        }
    }

    public class DirectoryChangeNotification
    {
        public FileNotificationAction Action { get; }
        public string FileName { get; }
        public string FullPath { get; }
        public string Win32Path { get; }

        internal DirectoryChangeNotification(string base_path, string win32_path, SafeStructureInOutBuffer<FileNotifyInformation> buffer) 
            : this(base_path, win32_path, buffer.Result, buffer.Data)
        {
        }

        private protected DirectoryChangeNotification(string base_path, string win32_path, IFileNotifyInformation info, SafeHGlobalBuffer buffer)
        {
            Action = info.GetAction();
            FileName = buffer.ReadUnicodeString(info.GetFileNameLength() / 2);
            FullPath = Path.Combine(base_path, FileName);
            Win32Path = Path.Combine(win32_path, FileName);
        }
    }

    public sealed class DirectoryChangeNotificationExtended : DirectoryChangeNotification
    {
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

        internal DirectoryChangeNotificationExtended(string base_path, string win32_path, SafeStructureInOutBuffer<FileNotifyExtendedInformation> buffer)
            : base(base_path, win32_path, buffer.Result, buffer.Data)
        {
            var info = buffer.Result;
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
        }
    }

    public enum DirectoryNotifyInformationClass
    {
        DirectoryNotifyInformation = 1,
        DirectoryNotifyExtendedInformation = 2
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Sid")]
    public struct FileGetQuotaInformation
    {
        public int NextEntryOffset;
        public int SidLength;
        public int Sid;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Sid")]
    public struct FileQuotaInformation
    {
        public int NextEntryOffset;
        public int SidLength;
        public LargeIntegerStruct ChangeTime;
        public LargeIntegerStruct QuotaUsed;
        public LargeIntegerStruct QuotaThreshold;
        public LargeIntegerStruct QuotaLimit;
        public int Sid;
    }

    /// <summary>
    /// Class to represent a file quota entry.
    /// </summary>
    public sealed class FileQuotaEntry
    {
        public Sid Sid { get; }
        public string User => Sid.Name;
        public DateTime ChangeTime { get; }
        public long QuotaUsed { get; set; }
        public long QuotaThreshold { get; set; }
        public long QuotaLimit { get; set; }
        public double QuotaPercent
        {
            get
            {
                if (QuotaThreshold <= 0)
                    return 0.0;
                return 100.0 * (QuotaUsed / (double)QuotaLimit);
            }
        }

        public FileQuotaEntry(Sid sid, long quota_threshold, long quota_limit)
        {
            Sid = sid;
            QuotaThreshold = quota_threshold;
            QuotaLimit = quota_limit;
        }

        internal FileQuotaEntry(SafeStructureInOutBuffer<FileQuotaInformation> buffer)
        {
            var info = buffer.Result;
            byte[] sid_data = buffer.Data.ReadBytes(info.SidLength);
            Sid = new Sid(sid_data);
            ChangeTime = info.ChangeTime.ToDateTime();
            QuotaUsed = info.QuotaUsed.QuadPart;
            QuotaThreshold = info.QuotaThreshold.QuadPart;
            QuotaLimit = info.QuotaLimit.QuadPart;
        }

        internal FileQuotaInformation ToInfo(int next_offset)
        {
            return new FileQuotaInformation()
            {
                NextEntryOffset = next_offset,
                SidLength = Sid.ToArray().Length,
                ChangeTime = new LargeIntegerStruct(),
                QuotaUsed = new LargeIntegerStruct(),
                QuotaThreshold = new LargeIntegerStruct() { QuadPart = QuotaThreshold },
                QuotaLimit = new LargeIntegerStruct() { QuadPart = QuotaLimit }
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileReparsePointInformation
    {
        public long FileReferenceNumber;
        public ReparseTag Tag;
    }

#pragma warning restore 1591
}
