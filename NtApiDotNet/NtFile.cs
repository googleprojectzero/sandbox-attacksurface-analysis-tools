//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet
{
    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern int NtOpenFile(
            out SafeKernelObjectHandle FileHandle,
            FileAccessRights DesiredAccess,
            ObjectAttributes ObjAttr,
            [In] [Out] IoStatus IoStatusBlock,
            FileShareMode ShareAccess,
            FileOpenOptions OpenOptions);

        [DllImport("ntdll.dll")]
        public static extern int NtCreateFile(
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
        public static extern int NtDeviceIoControlFile(
          SafeKernelObjectHandle FileHandle,
          SafeKernelObjectHandle Event,
          IntPtr ApcRoutine,
          IntPtr ApcContext,
          [Out] IoStatus IoStatusBlock,
          uint IoControlCode,
          IntPtr InputBuffer,
          int InputBufferLength,
          IntPtr OutputBuffer,
          int OutputBufferLength
        );

        [DllImport("ntdll.dll")]
        public static extern int NtFsControlFile(
          SafeKernelObjectHandle FileHandle,
          SafeKernelObjectHandle Event,
          IntPtr ApcRoutine,
          IntPtr ApcContext,
          [Out] IoStatus IoStatusBlock,
          uint FSControlCode,
          IntPtr InputBuffer,
          int InputBufferLength,
          IntPtr OutputBuffer,
          int OutputBufferLength
        );

        [DllImport("ntdll.dll")]
        public static extern int NtSetInformationFile(
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
        DATALINK = 0x00000005
        , DFS = 0x00000006
        , DFS_FILE_SYSTEM = 0x00000035
        , DFS_VOLUME = 0x00000036
        , DISK = 0x00000007
        , DISK_FILE_SYSTEM = 0x00000008
        , DVD = 0x00000033
        , FILE_SYSTEM = 0x00000009
        , FIPS = 0x0000003a
        , FULLSCREEN_VIDEO = 0x00000034
        , INPORT_PORT = 0x0000000a
        , KEYBOARD = 0x0000000b
        , KS = 0x0000002f
        , KSEC = 0x00000039
        , MAILSLOT = 0x0000000c
        , MASS_STORAGE = 0x0000002d
        , MIDI_IN = 0x0000000d
        , MIDI_OUT = 0x0000000e
        , MODEM = 0x0000002b
        , MOUSE = 0x0000000f
        , MULTI_UNC_PROVIDER = 0x00000010
        , NAMED_PIPE = 0x00000011
        , NETWORK = 0x00000012
        , NETWORK_BROWSER = 0x00000013
        , NETWORK_FILE_SYSTEM = 0x00000014
        , NETWORK_REDIRECTOR = 0x00000028
        , NULL = 0x00000015
        , PARALLEL_PORT = 0x00000016
        , PHYSICAL_NETCARD = 0x00000017
        , PRINTER = 0x00000018
        , SCANNER = 0x00000019
        , SCREEN = 0x0000001c
        , SERENUM = 0x00000037
        , SERIAL_MOUSE_PORT = 0x0000001a
        , SERIAL_PORT = 0x0000001b
        , SMARTCARD = 0x00000031
        , SMB = 0x0000002e
        , SOUND = 0x0000001d
        , STREAMS = 0x0000001e
        , TAPE = 0x0000001f
        , TAPE_FILE_SYSTEM = 0x00000020
        , TERMSRV = 0x00000038
        , TRANSPORT = 0x00000021
        , UNKNOWN = 0x00000022
        , VDM = 0x0000002c
        , VIDEO = 0x00000023
        , VIRTUAL_DISK = 0x00000024
        , WAVE_IN = 0x00000025
        , WAVE_OUT = 0x00000026
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

    public class NtFile : NtObjectWithDuplicate<NtFile, FileAccessRights>
    {
        internal NtFile(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        public static NtFile Create(ObjectAttributes obj_attributes, FileAccessRights desired_access, FileAttributes file_attributes, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer)
        {
            SafeKernelObjectHandle handle;
            IoStatus iostatus = new IoStatus();
            byte[] buffer = ea_buffer != null ? ea_buffer.ToByteArray() : null;
            int status = NtSystemCalls.NtCreateFile(out handle, desired_access, obj_attributes, iostatus, null, FileAttributes.Normal,
                share_access, disposition, open_options, buffer, buffer != null ? buffer.Length : 0);
            StatusToNtException(status);
            return new NtFile(handle);
        }

        public static NtFile Create(string name, NtObject root, FileAccessRights desired_access, FileAttributes file_attributes, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, desired_access, file_attributes, share_access, open_options, disposition, ea_buffer);
            }
        }

        public static NtFile Create(string name, FileAccessRights desired_access, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer)
        {
            return Create(name, null,  desired_access, FileAttributes.Normal, share_access, open_options, disposition, ea_buffer);
        }

        static IntPtr GetSafePointer(SafeHGlobalBuffer buffer)
        {
            return buffer != null ? buffer.DangerousGetHandle() : IntPtr.Zero;
        }

        static int GetSafeLength(SafeHGlobalBuffer buffer)
        {
            return buffer != null ? buffer.Length : 0;
        }

        public void DeviceIoControl(uint control_code, SafeHGlobalBuffer input_buffer, SafeHGlobalBuffer output_buffer)
        {
            IoStatus status = new IoStatus();
            StatusToNtException(NtSystemCalls.NtDeviceIoControlFile(Handle, SafeKernelObjectHandle.Null, IntPtr.Zero, IntPtr.Zero, status,
                control_code, GetSafePointer(input_buffer), GetSafeLength(input_buffer), GetSafePointer(output_buffer), GetSafeLength(output_buffer)));
        }

        public void FsControl(uint control_code, SafeHGlobalBuffer input_buffer, SafeHGlobalBuffer output_buffer)
        {
            IoStatus status = new IoStatus();
            StatusToNtException(NtSystemCalls.NtFsControlFile(Handle, SafeKernelObjectHandle.Null, IntPtr.Zero, IntPtr.Zero, status,
                control_code, GetSafePointer(input_buffer), GetSafeLength(input_buffer), GetSafePointer(output_buffer), GetSafeLength(output_buffer)));
        }

        public static NtFile Open(ObjectAttributes obj_attributes, FileAccessRights DesiredAccess, FileShareMode ShareAccess, FileOpenOptions OpenOptions)
        {
            SafeKernelObjectHandle handle;
            IoStatus iostatus = new IoStatus();
            StatusToNtException(NtSystemCalls.NtOpenFile(out handle, DesiredAccess, obj_attributes, iostatus, ShareAccess, OpenOptions));
            return new NtFile(handle);
        }

        public static NtFile Open(string name, NtObject root, FileAccessRights DesiredAccess, FileShareMode ShareAccess, FileOpenOptions OpenOptions)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, DesiredAccess, ShareAccess, OpenOptions);
            }
        }

        public string GetFileId()
        {
            using (var internal_info = new SafeStructureInOutBuffer<FileInternalInformation>())
            {
                IoStatus iostatus = new IoStatus();
                StatusToNtException(NtSystemCalls.NtQueryInformationFile(Handle, iostatus, internal_info, internal_info.Length, FileInformationClass.FileInternalInformation));
                return Encoding.Unicode.GetString(BitConverter.GetBytes(internal_info.Result.IndexNumber.QuadPart));
            }
        }

        public FileAttributes GetFileAttributes()
        {
            using (var basic_info = new SafeStructureInOutBuffer<FileBasicInformation>())
            {
                IoStatus iostatus = new IoStatus();
                StatusToNtException(NtSystemCalls.NtQueryInformationFile(Handle, iostatus, basic_info, basic_info.Length, FileInformationClass.FileBasicInformation));
                return basic_info.Result.FileAttributes;
            }
        }

        public static string GetFileId(string path)
        {
            using (NtFile file = NtFile.Open(path, null, FileAccessRights.MaximumAllowed, FileShareMode.None, FileOpenOptions.None))
            {
                return file.GetFileId();
            }
        }

        public static NtFile OpenFileById(NtFile volume, string id,
            FileAccessRights DesiredAccess, FileShareMode ShareAccess, FileOpenOptions OpenOptions, bool inherit)
        {
            AttributeFlags flags = AttributeFlags.CaseInsensitive;
            if (inherit)
                flags |= AttributeFlags.Inherit;
            StringBuilder name_builder = new StringBuilder();
            using (ObjectAttributes obja = new ObjectAttributes(id, flags, volume, null, null))
            {
                SafeKernelObjectHandle handle;
                IoStatus iostatus = new IoStatus();
                StatusToNtException(NtSystemCalls.NtOpenFile(out handle, DesiredAccess, obja,
                    iostatus, ShareAccess, OpenOptions | FileOpenOptions.OpenByFileId));
                return new NtFile(handle);
            }
        }

        public void Delete()
        {
            IoStatus iostatus = new IoStatus();
            using (var deletefile = new FileDispositionInformation() { DeleteFile = true }.ToBuffer())
            {
                StatusToNtException(NtSystemCalls.NtSetInformationFile(Handle, iostatus, deletefile,
                    deletefile.Length, FileInformationClass.FileDispositionInformation));
            }
        }

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
                StatusToNtException(NtSystemCalls.NtSetInformationFile(Handle, iostatus, buffer,
                        buffer.Length, FileInformationClass.FileLinkInformation));
            }
        }

        public void CreateHardlink(string linkname)
        {
            CreateHardlink(linkname, (NtFile)null);
        }

        public static void CreateHardlink(string path, string linkname)
        {
            using (NtFile file = Open(path, null, FileAccessRights.MaximumAllowed,
                FileShareMode.Read, FileOpenOptions.NonDirectoryFile))
            {
                file.CreateHardlink(linkname);
            }
        }

        public FileStream ToStream(bool writeable)
        {
            SafeFileHandle handle = NtObject.DuplicateAsFile(Handle);
            return new FileStream(handle, FileAccess.Read | (writeable ? FileAccess.Write : 0));
        }

        [Flags]
        public enum FinalPathNameFlags
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

        public string GetWin32PathName()
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

        public FileDeviceType GetDeviceType()
        {
            using (SafeStructureInOutBuffer<FileFsDeviceInformation> file_info = new SafeStructureInOutBuffer<FileFsDeviceInformation>())
            {
                IoStatus status = new IoStatus();
                StatusToNtException(NtSystemCalls.NtQueryVolumeInformationFile(Handle, status, file_info, 
                    file_info.Length, FsInformationClass.FileFsDeviceInformation));
                return file_info.Result.DeviceType;
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
                    IoStatus status = new NtApiDotNet.IoStatus();
                    StatusToNtException(NtSystemCalls.NtQueryInformationFile(Handle, status, buffer, buffer.Length, FileInformationClass.FileNameInformation));
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

        public override string GetName()
        {
            if (GetDeviceType() != FileDeviceType.NAMED_PIPE)
            {
                return base.GetName();
            }
            else
            {
                Console.WriteLine("Granted Access: {0}", GetGrantedAccessString());
                return base.GetName();
            }
        }
    }

    public static class FileUtils
    {
        public static string DosFileNameToNt(string filename)
        {
            UnicodeStringOut nt_name = new UnicodeStringOut();
            try
            {
                IntPtr short_path;
                NtObject.StatusToNtException(NtRtl.RtlDosPathNameToRelativeNtPathName_U_WithStatus(filename, out nt_name, out short_path, null));
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

        public static ObjectAttributes DosFileNameToObjectAttributes(string filename)
        {
            UnicodeStringOut nt_name = new UnicodeStringOut();
            RtlRelativeName relative_name = new RtlRelativeName();
            try
            {
                IntPtr short_path;
                NtObject.StatusToNtException(NtRtl.RtlDosPathNameToRelativeNtPathName_U_WithStatus(filename, out nt_name, out short_path, relative_name));
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

        public static UnicodeString DosFileNameToUnicodeString(string filename)
        {
            return new UnicodeString(DosFileNameToNt(filename));
        }

        public static RtlPathType GetDosPathType(string filename)
        {
            return NtRtl.RtlDetermineDosPathNameType_U(filename);
        }
    }
}
