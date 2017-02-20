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
using System.Runtime.InteropServices;
using System.Text;

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
            [In] [Out] IoStatus IoStatusBlock,
            FileShareMode ShareAccess,
            FileOpenOptions OpenOptions);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateFile(
            out SafeKernelObjectHandle FileHandle,
            FileAccessRights DesiredAccess,
            ObjectAttributes ObjAttr,
            [In] [Out] IoStatus IoStatusBlock,
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
          [Out] IoStatus IoStatusBlock,
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
          [Out] IoStatus IoStatusBlock,
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
            IoStatus IoStatusBlock,
            SafeBuffer FileInformation,
            int Length,
            FileInformationClass FileInformationClass);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryVolumeInformationFile(
          SafeKernelObjectHandle FileHandle,
          IoStatus IoStatusBlock,
          SafeBuffer FsInformation,
          int Length,
          FsInformationClass FsInformationClass);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryDirectoryFile(
          SafeKernelObjectHandle FileHandle,
          SafeKernelObjectHandle Event,
          IntPtr ApcRoutine,
          IntPtr ApcContext,
          [Out] IoStatus IoStatusBlock,
          SafeBuffer FileInformation,
          int Length,
          FileInformationClass FileInformationClass,
          [MarshalAs(UnmanagedType.U1)] bool ReturnSingleEntry,
          UnicodeString FileName,
          [MarshalAs(UnmanagedType.U1)] bool RestartScan
        );
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

    [StructLayout(LayoutKind.Sequential), DataStart("FileName")]
    struct FileDirectoryInformation
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

    public class IoStatus
    {
        public IntPtr Pointer;
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
    /// Represnt a NT file IO control code.
    /// </summary>
    public class NtIoControlCode
    {
        /// <summary>
        /// Type of device
        /// </summary>
        public FileDeviceType DeviceType { get; private set; }
        /// <summary>
        /// Function number
        /// </summary>
        public int Function { get; private set; }
        /// <summary>
        /// Buffering method
        /// </summary>
        public FileControlMethod Method { get; private set; }
        /// <summary>
        /// Access of file handle
        /// </summary>
        public FileControlAccess Access { get; private set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="device_type">Type of device</param>
        /// <param name="function">Function number</param>
        /// <param name="method">Buffering method</param>
        /// <param name="access">Access of file handle</param>
        public NtIoControlCode(FileDeviceType device_type, int function, FileControlMethod method, FileControlAccess access)
        {
            DeviceType = device_type;
            Function = function;
            Method = method;
            Access = access;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="code">Raw IO control code to convert.</param>
        public NtIoControlCode(int code)
        {
            DeviceType = (FileDeviceType)(code >> 16);
            Access = (FileControlAccess)((code >> 14) & 3);
            Function = (code >> 2) & 0xFFF;
            Method = (FileControlMethod)(code & 3);
        }

        /// <summary>
        /// Convert the io control code to an Int32
        /// </summary>
        /// <returns>The int32 version of the code</returns>
        public int ToInt32()
        {
            return (((int)DeviceType) << 16) | (((int)Access) << 14) | (((int)Function) << 2) | ((int)Method);
        }
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



#pragma warning restore 1591

    /// <summary>
    /// Class representing a NT File object
    /// </summary>
    public class NtFile : NtObjectWithDuplicate<NtFile, FileAccessRights>
    {
        internal NtFile(SafeKernelObjectHandle handle) : base(handle)
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
        /// <returns>The created/opened file object.</returns>
        public static NtFile Create(ObjectAttributes obj_attributes, FileAccessRights desired_access, FileAttributes file_attributes, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer)
        {
            SafeKernelObjectHandle handle;
            IoStatus iostatus = new IoStatus();
            byte[] buffer = ea_buffer != null ? ea_buffer.ToByteArray() : null;
            NtSystemCalls.NtCreateFile(out handle, desired_access, obj_attributes, iostatus, null, FileAttributes.Normal,
                share_access, disposition, open_options, buffer, buffer != null ? buffer.Length : 0).ToNtException();
            return new NtFile(handle);
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
            return Create(name, null,  desired_access, FileAttributes.Normal, share_access, open_options, disposition, ea_buffer);
        }

        static IntPtr GetSafePointer(SafeBuffer buffer)
        {
            return buffer != null ? buffer.DangerousGetHandle() : IntPtr.Zero;
        }

        static int GetSafeLength(SafeBuffer buffer)
        {
            return buffer != null ? (int)buffer.ByteLength : 0;
        }

        /// <summary>
        /// Send an Device IO Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <returns>The length of output bytes returned.</returns>
        public int DeviceIoControl(int control_code, SafeBuffer input_buffer, SafeBuffer output_buffer)
        {
            IoStatus status = new IoStatus();
            NtStatus result = NtSystemCalls.NtDeviceIoControlFile(Handle, SafeKernelObjectHandle.Null, IntPtr.Zero, IntPtr.Zero, status,
                control_code, GetSafePointer(input_buffer), GetSafeLength(input_buffer), GetSafePointer(output_buffer), GetSafeLength(output_buffer)).ToNtException();
            if (result == NtStatus.STATUS_PENDING)
            {
                Wait().ToNtException();
            }
            return status.Information.ToInt32();
        }

        /// <summary>
        /// Send an File System Control code to the file driver
        /// </summary>
        /// <param name="control_code">The control code</param>
        /// <param name="input_buffer">Input buffer can be null</param>
        /// <param name="output_buffer">Output buffer can be null</param>
        /// <returns>The length of output bytes returned.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int FsControl(int control_code, SafeBuffer input_buffer, SafeBuffer output_buffer)
        {
            IoStatus status = new IoStatus();
            NtStatus result = NtSystemCalls.NtFsControlFile(Handle, SafeKernelObjectHandle.Null, IntPtr.Zero, IntPtr.Zero, status,
                control_code, GetSafePointer(input_buffer), GetSafeLength(input_buffer), GetSafePointer(output_buffer), GetSafeLength(output_buffer)).ToNtException();
            if (result == NtStatus.STATUS_PENDING)
            {
                Wait().ToNtException();
            }
            return status.Information.ToInt32();
        }        

        /// <summary>
        /// Open a file
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>
        /// <param name="DesiredAccess">The desired access for the file handle</param>
        /// <param name="ShareAccess">The file share access</param>
        /// <param name="OpenOptions">File open options</param>
        /// <returns>The opened file</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtFile Open(ObjectAttributes obj_attributes, FileAccessRights DesiredAccess, FileShareMode ShareAccess, FileOpenOptions OpenOptions)
        {
            SafeKernelObjectHandle handle;
            IoStatus iostatus = new IoStatus();
            NtSystemCalls.NtOpenFile(out handle, DesiredAccess, obj_attributes, iostatus, ShareAccess, OpenOptions).ToNtException();
            return new NtFile(handle);
        }

        /// <summary>
        /// Open a file
        /// </summary>
        /// <param name="path">The path to the file</param>
        /// <param name="root">The root directory if path is relative.</param>
        /// <param name="DesiredAccess">The desired access for the file handle</param>
        /// <param name="ShareAccess">The file share access</param>
        /// <param name="OpenOptions">File open options</param>
        /// <returns>The opened file</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtFile Open(string path, NtObject root, FileAccessRights DesiredAccess, FileShareMode ShareAccess, FileOpenOptions OpenOptions)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, DesiredAccess, ShareAccess, OpenOptions);
            }
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
                using (var internal_info = new SafeStructureInOutBuffer<FileInternalInformation>())
                {
                    IoStatus iostatus = new IoStatus();
                    NtSystemCalls.NtQueryInformationFile(Handle, iostatus, internal_info, internal_info.Length, FileInformationClass.FileInternalInformation).ToNtException();
                    return Encoding.Unicode.GetString(BitConverter.GetBytes(internal_info.Result.IndexNumber.QuadPart));
                }
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
                using (var basic_info = new SafeStructureInOutBuffer<FileBasicInformation>())
                {
                    IoStatus iostatus = new IoStatus();
                    NtSystemCalls.NtQueryInformationFile(Handle, iostatus, basic_info, basic_info.Length, FileInformationClass.FileBasicInformation).ToNtException();
                    return basic_info.Result.FileAttributes;
                }
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
        /// <param name="DesiredAccess">The desired access for the file</param>
        /// <param name="ShareAccess">File share access</param>
        /// <param name="OpenOptions">Open options.</param>
        /// <returns>The opened file object</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtFile OpenFileById(NtFile volume, string id,
            FileAccessRights DesiredAccess, FileShareMode ShareAccess, FileOpenOptions OpenOptions)
        {
            StringBuilder name_builder = new StringBuilder();
            using (ObjectAttributes obja = new ObjectAttributes(id, AttributeFlags.CaseInsensitive, volume, null, null))
            {
                SafeKernelObjectHandle handle;
                IoStatus iostatus = new IoStatus();
                NtSystemCalls.NtOpenFile(out handle, DesiredAccess, obja,
                    iostatus, ShareAccess, OpenOptions | FileOpenOptions.OpenByFileId).ToNtException();
                return new NtFile(handle);
            }
        }

        /// <summary>
        /// Delete the file. Must have been opened with DELETE access.
        /// </summary>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Delete()
        {
            IoStatus iostatus = new IoStatus();
            using (var deletefile = new FileDispositionInformation() { DeleteFile = true }.ToBuffer())
            {
                NtSystemCalls.NtSetInformationFile(Handle, iostatus, deletefile,
                    deletefile.Length, FileInformationClass.FileDispositionInformation).ToNtException();
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
                        buffer.Length, FileInformationClass.FileLinkInformation).ToNtException();
            }
        }

        /// <summary>
        /// Create a new hardlink to this file.
        /// </summary>
        /// <param name="linkname">The target absolute NT path.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void CreateHardlink(string linkname)
        {
            CreateHardlink(linkname, (NtFile)null);
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
        
        static NtIoControlCode FSCTL_SET_REPARSE_POINT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 41, FileControlMethod.Buffered, FileControlAccess.Any);
        static NtIoControlCode FSCTL_GET_REPARSE_POINT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 42, FileControlMethod.Buffered, FileControlAccess.Any);
        static NtIoControlCode FSCTL_DELETE_REPARSE_POINT = new NtIoControlCode(FileDeviceType.FILE_SYSTEM, 43, FileControlMethod.Buffered, FileControlAccess.Any);

        private void SetReparsePoint(ReparseBuffer reparse)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(reparse.ToByteArray()))
            {
                FsControl(FSCTL_SET_REPARSE_POINT.ToInt32(), buffer, null);
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
                FsControl(FSCTL_GET_REPARSE_POINT.ToInt32(), null, buffer);
                
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
                FsControl(FSCTL_DELETE_REPARSE_POINT.ToInt32(), buffer, null);
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
        /// Query a directory for files.
        /// </summary>
        /// <param name="file_mask">A file name mask (such as *.txt). Can be null.</param>
        /// <param name="type_mask">Indicate what entries to return.</param>
        /// <returns></returns>
        public IEnumerable<FileDirectoryEntry> QueryDirectoryInfo(string file_mask, FileTypeMask type_mask)
        {
            UnicodeString mask = file_mask != null ? new UnicodeString(file_mask) : null;
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(128 * 1024))
            {
                IoStatus io_status = new IoStatus();
                NtStatus status = NtSystemCalls.NtQueryDirectoryFile(Handle, SafeKernelObjectHandle.Null, IntPtr.Zero, IntPtr.Zero, io_status, buffer, buffer.Length, FileInformationClass.FileDirectoryInformation, false, mask, true);
                if (status == NtStatus.STATUS_PENDING)
                {
                    status = Wait().ToNtException();
                }

                while (status != NtStatus.STATUS_NO_MORE_FILES)
                {
                    SafeStructureInOutBuffer<FileDirectoryInformation> dir_buffer = buffer.GetStructAtOffset<FileDirectoryInformation>(0);
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

                    io_status = new IoStatus();
                    status = NtSystemCalls.NtQueryDirectoryFile(Handle, SafeKernelObjectHandle.Null, IntPtr.Zero, IntPtr.Zero,
                        io_status, buffer, buffer.Length, FileInformationClass.FileDirectoryInformation, false, mask, false);
                    if (status == NtStatus.STATUS_PENDING)
                    {
                        status = Wait().ToNtException();
                    }
                }
            }
        }

        private static SafeFileHandle DuplicateAsFile(SafeHandle handle)
        {
            using (SafeKernelObjectHandle dup_handle = DuplicateHandle(NtProcess.Current, handle, NtProcess.Current))
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

            if (NtType.HasWritePermission(GrantedAccessRaw))
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
                    return GetPathNameInternal(FinalPathNameFlags.None);
                }
                catch (Win32Exception)
                {
                    return String.Empty;
                }
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
                using (SafeStructureInOutBuffer<FileFsDeviceInformation> file_info = new SafeStructureInOutBuffer<FileFsDeviceInformation>())
                {
                    IoStatus status = new IoStatus();
                    NtSystemCalls.NtQueryVolumeInformationFile(Handle, status, file_info,
                        file_info.Length, FsInformationClass.FileFsDeviceInformation).ToNtException();
                    return file_info.Result.DeviceType;
                }
            }
        }

        [DllImport("kernel32.dll")]
        private static extern int GetFileType(SafeKernelObjectHandle handle);

        private string TryGetName()
        {
            using (SafeStructureInOutBuffer<FileNameInformation> buffer = new SafeStructureInOutBuffer<FileNameInformation>(32 * 1024, true))
            {
                try
                {
                    IoStatus status = new IoStatus();
                    NtSystemCalls.NtQueryInformationFile(Handle, status, buffer, buffer.Length, FileInformationClass.FileNameInformation).ToNtException();
                    char[] result = new char[buffer.Result.NameLength / 2];
                    buffer.Data.ReadArray(0, result, 0, result.Length);
                    return new string(result);
                }
                catch (NtException)
                {
                    return String.Empty;
                }
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
    }
}
