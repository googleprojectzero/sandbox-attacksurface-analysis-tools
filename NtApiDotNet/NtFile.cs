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
    /// <summary>
    /// Class representing a NT File object
    /// </summary>
    [NtType("File"), NtType("Device"), NtType("Driver", DisableOpen = true)]
    public class NtFile : NtObjectWithDuplicateAndInfo<NtFile, FileAccessRights, FileInformationClass, FileInformationClass>
    {
        #region Constructors

        internal NtFile(SafeKernelObjectHandle handle, IoStatus io_status) : base(handle)
        {
            _cts = new CancellationTokenSource();
            OpenResult = io_status != null ? (FileOpenResult)io_status.Information.ToInt32() : FileOpenResult.Opened;
            _sync_mode = new Lazy<bool>(() => Mode.HasFlagSet(FileOpenOptions.SynchronousIoAlert | FileOpenOptions.SynchronousIoNonAlert));
        }

        internal NtFile(SafeKernelObjectHandle handle)
            : this(handle, null)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(typeof(FileDirectoryAccessRights), true)
            {
            }

            protected override sealed NtResult<NtFile> OpenInternal(ObjectAttributes obj_attributes,
                FileAccessRights desired_access, bool throw_on_error)
            {
                return NtFile.Open(obj_attributes, desired_access,
                    FileShareMode.Read | FileShareMode.Delete,
                    FileOpenOptions.None, throw_on_error);
            }
        }

        #endregion

        #region Private Members
        // Cancellation source for stopping pending IO on close.
        private CancellationTokenSource _cts;
        private bool? _is_directory;
        private readonly Lazy<bool> _sync_mode;

        private const int ChangeNotificationBufferSize = 64 * 1024;

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
            switch (GetDeviceType(handle))
            {
                case FileDeviceType.NAMED_PIPE:
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
            CheckForSyncMode();
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
            return RunFileCallSync(r => func(Handle, r.EventHandle, IntPtr.Zero, IntPtr.Zero, r.IoStatusBuffer,
                    control_code.ToInt32(), GetSafePointer(input_buffer), GetSafeLength(input_buffer), GetSafePointer(output_buffer),
                    GetSafeLength(output_buffer)), throw_on_error).Map(s => s.Information32);
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

        private NtStatus DoLinkRenameEx(FileInformationClass file_info, string filename, NtObject root, FileRenameInformationExFlags flags, bool throw_on_error)
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
                return SetBuffer(file_info, buffer, throw_on_error);
            }
        }

        private NtStatus DoLinkRename(FileInformationClass file_info, string linkname, NtObject root, bool replace_if_exists, bool throw_on_error)
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
                return SetBuffer(file_info, buffer, throw_on_error);
            }
        }

        private void CheckForSyncMode()
        {
            if (_sync_mode.Value)
                throw new ArgumentException("File was opened synchronously. Can't perform asynchronous operations.");
        }

        private async Task<NtResult<IoStatus>> RunFileCallAsync(Func<NtAsyncResult, NtStatus> func, CancellationToken token, bool throw_on_error)
        {
            CheckForSyncMode();

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

        private NtResult<IoStatus> RunFileCallSync(Func<NtAsyncResult, NtStatus> func, NtWaitTimeout timeout, bool throw_on_error)
        {
            if (timeout?.Timeout != null)
                CheckForSyncMode();
            using (NtAsyncResult result = new NtAsyncResult(this))
            {
                return result.CompleteCall(func(result), timeout)
                    .CreateResult(throw_on_error, () => result.IoStatusBuffer.Result);
            }
        }

        private NtResult<IoStatus> RunFileCallSync(Func<NtAsyncResult, NtStatus> func, bool throw_on_error)
        {
            return RunFileCallSync(func, NtWaitTimeout.Infinite, throw_on_error);
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

        private static FileFsFullSizeInformationEx ConvertToSizeEx(FileFsFullSizeInformation size)
        {
            return new FileFsFullSizeInformationEx()
            {
                BytesPerSector = size.BytesPerSector,
                SectorsPerAllocationUnit = size.SectorsPerAllocationUnit,
                ActualAvailableAllocationUnits = size.ActualAvailableAllocationUnits.ToUInt64(),
                CallerAvailableAllocationUnits = size.CallerAvailableAllocationUnits.ToUInt64(),
                ActualTotalAllocationUnits = size.TotalAllocationUnits.ToUInt64()
            };
        }

        private NtResult<FileFsFullSizeInformationEx> QueryVolumeSize(bool throw_on_error)
        {
            var ex_result = QueryVolumeFixed<FileFsFullSizeInformationEx>(FsInformationClass.FileFsFullSizeInformationEx, false);
            if (ex_result.IsSuccess)
                return ex_result;
            return QueryVolumeFixed<FileFsFullSizeInformation>(FsInformationClass.FileFsFullSizeInformation, throw_on_error).Map(ConvertToSizeEx);
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

        private NtResult<string> TryGetName(FileInformationClass info_class, bool throw_on_error)
        {
            using (var buffer = new SafeStructureInOutBuffer<FileNameInformation>(32 * 1024, true))
            {
                IoStatus status = new IoStatus();
                NtStatus nt_status = NtSystemCalls.NtQueryInformationFile(Handle,
                    status, buffer, buffer.Length, info_class);
                if (!nt_status.IsSuccess())
                    return nt_status.CreateResultFromError<string>(throw_on_error);
                char[] result = new char[buffer.Result.NameLength / 2];
                buffer.Data.ReadArray(0, result, 0, result.Length);
                return new string(result).CreateResult();
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

        private static NtIoControlCode GetOplockAckFsctl(OplockAcknowledgeLevel level)
        {
            switch (level)
            {
                case OplockAcknowledgeLevel.Acknowledge:
                    return NtWellKnownIoControlCodes.FSCTL_OPLOCK_BREAK_ACKNOWLEDGE;
                case OplockAcknowledgeLevel.ClosePending:
                    return NtWellKnownIoControlCodes.FSCTL_OPBATCH_ACK_CLOSE_PENDING;
                case OplockAcknowledgeLevel.No2:
                    return NtWellKnownIoControlCodes.FSCTL_OPLOCK_BREAK_ACK_NO_2;
                default:
                    throw new ArgumentException("Invalid oplock acknowledge level", "level");
            }
        }

        private static FileSegmentElement[] PageListToSegments(IEnumerable<long> pages)
        {
            return pages.Select(p => new FileSegmentElement() { Buffer = new IntPtr(p) }).Concat(new[] { new FileSegmentElement() }).ToArray();
        }

        private NtResult<FileBasicInformation> QueryBasicInformation(bool throw_on_error)
        {
            return Query(FileInformationClass.FileBasicInformation, new FileBasicInformation(), throw_on_error);
        }

        private NtStatus SetBasicInformation(FileBasicInformation basic_info, bool throw_on_error)
        {
            return Set(FileInformationClass.FileBasicInformation, basic_info, throw_on_error);
        }

        private IEnumerable<DirectoryChangeNotification> ReadNotifications(SafeHGlobalBuffer buffer, IoStatus status)
        {
            List<DirectoryChangeNotification> ns = new List<DirectoryChangeNotification>();

            // Change buffer size to reflect what's in the buffer.
            buffer.Initialize((uint)status.Information32);

            int offset = 0;
            string full_path = FullPath;
            string win32_path = Win32PathName;
            while (offset < buffer.Length)
            {
                var info = buffer.GetStructAtOffset<FileNotifyInformation>(offset);
                var result = info.Result;
                ns.Add(new DirectoryChangeNotification(full_path, win32_path, info));
                if (result.NextEntryOffset == 0)
                {
                    break;
                }
                offset += result.NextEntryOffset;
            }
            return ns.AsReadOnly();
        }

        private IEnumerable<DirectoryChangeNotificationExtended> ReadExtendedNotifications(SafeHGlobalBuffer buffer, IoStatus status)
        {
            List<DirectoryChangeNotificationExtended> ns = new List<DirectoryChangeNotificationExtended>();

            // Change buffer size to reflect what's in the buffer.
            buffer.Initialize((uint)status.Information32);
            string full_path = FullPath;
            string win32_path = Win32PathName;
            int offset = 0;
            while (offset < buffer.Length)
            {
                var info = buffer.GetStructAtOffset<FileNotifyExtendedInformation>(offset);
                var result = info.Result;
                ns.Add(new DirectoryChangeNotificationExtended(full_path, win32_path, info));
                if (result.NextEntryOffset == 0)
                {
                    break;
                }
                offset += result.NextEntryOffset;
            }
            return ns.AsReadOnly();
        }

        private IEnumerable<T> QueryFixedDirectoryEntries<T>(FileInformationClass info_class) where T : struct
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                using (NtAsyncResult result = new NtAsyncResult(this))
                {
                    NtStatus status = result.CompleteCall(NtSystemCalls.NtQueryDirectoryFile(Handle, result.EventHandle,
                        IntPtr.Zero, IntPtr.Zero, result.IoStatusBuffer, buffer, buffer.Length,
                        info_class, true, null, true));

                    while (status.IsSuccess())
                    {
                        yield return buffer.Result;
                        result.Reset();
                        status = result.CompleteCall(NtSystemCalls.NtQueryDirectoryFile(Handle, result.EventHandle, IntPtr.Zero, IntPtr.Zero,
                            result.IoStatusBuffer, buffer, buffer.Length, info_class, true, null, false));
                    }

                    if (status != NtStatus.STATUS_NO_MORE_FILES && status != NtStatus.STATUS_NO_SUCH_FILE)
                    {
                        status.ToNtException();
                    }
                }
            }
        }

        private IEnumerable<U> QueryDirectoryInfo<T, U>(FileInformationClass info_class, string file_mask, FileTypeMask type_mask, bool include_placeholders) where T : struct, IFileDirectoryInformation<T, U> where U : FileDirectoryEntry
        {
            UnicodeString mask = new UnicodeString(string.IsNullOrEmpty(file_mask) ? "*" : file_mask);
            // 32k seems to be a reasonable size, too big and some volumes will fail with STATUS_INVALID_PARAMETER.
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(32 * 1024))
            {
                using (NtAsyncResult result = new NtAsyncResult(this))
                {
                    NtStatus status = result.CompleteCall(NtSystemCalls.NtQueryDirectoryFile(Handle, result.EventHandle,
                        IntPtr.Zero, IntPtr.Zero, result.IoStatusBuffer, buffer, buffer.Length,
                        info_class, false, mask, true));

                    while (status.IsSuccess())
                    {
                        var dir_buffer = buffer.GetStructAtOffset<T>(0);
                        do
                        {
                            var dir_info = dir_buffer.Result;
                            bool valid_entry = false;
                            switch (type_mask)
                            {
                                case FileTypeMask.All:
                                    valid_entry = true;
                                    break;
                                case FileTypeMask.FilesOnly:
                                    valid_entry = !dir_info.GetAttributes().HasFlagSet(FileAttributes.Directory);
                                    break;
                                case FileTypeMask.DirectoriesOnly:
                                    valid_entry = dir_info.GetAttributes().HasFlagSet(FileAttributes.Directory);
                                    break;
                            }

                            if (valid_entry)
                            {
                                var entry = dir_info.ToEntry(dir_buffer);
                                if (include_placeholders || (entry.FileName != "." && entry.FileName != ".."))
                                {
                                    yield return entry;
                                }
                            }

                            int nextofs = dir_info.GetNextOffset();

                            if (nextofs == 0)
                            {
                                break;
                            }
                            dir_buffer = dir_buffer.GetStructAtOffset<T>(nextofs);
                        }
                        while (true);

                        result.Reset();
                        status = result.CompleteCall(NtSystemCalls.NtQueryDirectoryFile(Handle, result.EventHandle, IntPtr.Zero, IntPtr.Zero,
                            result.IoStatusBuffer, buffer, buffer.Length, info_class, false, mask, false));
                    }

                    if (status != NtStatus.STATUS_NO_MORE_FILES && status != NtStatus.STATUS_NO_SUCH_FILE)
                    {
                        status.ToNtException();
                    }
                }
            }
        }

        private static SafeHGlobalBuffer ConvertSidList(IEnumerable<Sid> sid_list, DisposableList list)
        {
            if (sid_list == null || !sid_list.Any())
            {
                return SafeHGlobalBuffer.Null;
            }

            int struct_size = Marshal.SizeOf(typeof(FileGetQuotaInformation)) - 4;
            List<byte[]> sids = sid_list.Select(s => s.ToArray()).ToList();
            int total_size = sids.Sum(b => b.Length + struct_size);

            var buffer = list.AddResource(new SafeHGlobalBuffer(total_size));
            int offset = 0;

            for (int i = 0; i < sids.Count; ++i)
            {
                var curr = buffer.GetStructAtOffset<FileGetQuotaInformation>(offset);
                byte[] sid = sids[i];

                int next_offset = i < sids.Count - 1 ? struct_size + sid.Length : 0;
                curr.Result = new FileGetQuotaInformation() { NextEntryOffset = next_offset, SidLength = sid.Length };
                curr.Data.WriteBytes(sid);
                offset += next_offset;
            }

            return buffer;
        }

        private static SafeHGlobalBuffer ConvertQuotaEntries(FileQuotaEntry[] quota_entries, DisposableList list)
        {
            int struct_size = Marshal.SizeOf(typeof(FileQuotaInformation)) - 4;
            List<byte[]> sids = quota_entries.Select(q => q.Sid.ToArray()).ToList();
            int total_size = sids.Sum(b => b.Length + struct_size);

            var buffer = list.AddResource(new SafeHGlobalBuffer(total_size));
            int offset = 0;

            for (int i = 0; i < sids.Count; ++i)
            {
                var curr = buffer.GetStructAtOffset<FileQuotaInformation>(offset);
                byte[] sid = sids[i];

                int next_offset = i < sids.Count - 1 ? struct_size + sid.Length : 0;
                curr.Result = quota_entries[i].ToInfo(next_offset);
                curr.Data.WriteBytes(sid);
                offset += next_offset;
            }

            return buffer;
        }

        private IEnumerable<FileQuotaEntry> QueryQuota(IEnumerable<Sid> sid_list, Sid start_sid)
        {
            using (var list = new DisposableList())
            {
                var buffer = list.AddResource(new SafeStructureInOutBuffer<FileQuotaInformation>(32 * 1024, false));
                SafeHGlobalBuffer sid_list_buffer = ConvertSidList(sid_list, list);
                SafeSidBufferHandle start_sid_buffer = SafeSidBufferHandle.Null;
                if (start_sid != null)
                {
                    start_sid_buffer = start_sid.ToSafeBuffer();
                }

                IoStatus io_status = new IoStatus();
                NtStatus status = NtSystemCalls.NtQueryQuotaInformationFile(Handle,
                        io_status, buffer, buffer.Length, false, sid_list_buffer, sid_list_buffer.Length,
                        start_sid_buffer, true);
                while(status.IsSuccess())
                {
                    int offset = 0;
                    while (true)
                    {
                        var next_buffer = buffer.GetStructAtOffset<FileQuotaInformation>(offset);
                        var result = next_buffer.Result;

                        yield return new FileQuotaEntry(next_buffer);

                        if (result.NextEntryOffset == 0)
                            break;
                        offset += result.NextEntryOffset;
                    }

                    if (start_sid != null)
                    {
                        break;
                    }

                    // If a SID list then this will just repeat.
                    if (sid_list?.Any() ?? false)
                    {
                        break;
                    }

                    status = NtSystemCalls.NtQueryQuotaInformationFile(Handle,
                        io_status, buffer, buffer.Length, false, sid_list_buffer, sid_list_buffer.Length,
                        start_sid_buffer, false);
                }

                if (status != NtStatus.STATUS_NO_MORE_ENTRIES)
                {
                    status.ToNtException();
                }
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
        /// <param name="allocation_size">Optional allocation size.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtFile> Create(ObjectAttributes obj_attributes, FileAccessRights desired_access, FileAttributes file_attributes, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer, long? allocation_size, bool throw_on_error)
        {
            IoStatus iostatus = new IoStatus();
            byte[] buffer = ea_buffer?.ToByteArray();
            return NtSystemCalls.NtCreateFile(out SafeKernelObjectHandle handle, desired_access, obj_attributes, iostatus, allocation_size.ToLargeInteger(), file_attributes,
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
        /// <param name="allocation_size">Optional allocation size.</param>
        /// <returns>The created/opened file object.</returns>
        public static NtFile Create(ObjectAttributes obj_attributes, FileAccessRights desired_access, FileAttributes file_attributes, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer, long? allocation_size)
        {
            return Create(obj_attributes, desired_access, file_attributes, share_access, open_options, disposition, ea_buffer, allocation_size, true).Result;
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
            return Create(obj_attributes, desired_access, file_attributes,
                share_access, open_options, disposition, ea_buffer, null, throw_on_error);
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
            return Create(obj_attributes, desired_access, file_attributes, share_access, open_options, disposition, ea_buffer, null);
        }

        /// <summary>
        /// Create a new file
        /// </summary>
        /// <param name="path">The path to the file</param>
        /// <param name="root">A root object to parse relative filenames</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="file_attributes">Attributes for the file</param>
        /// <param name="share_access">Share access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="disposition">Disposition when opening the file</param>
        /// <param name="ea_buffer">Extended Attributes buffer</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The created/opened file object.</returns>
        public static NtResult<NtFile> Create(string path, NtObject root, FileAccessRights desired_access, FileAttributes file_attributes, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer, bool throw_on_error)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, desired_access, file_attributes, share_access, open_options, disposition, ea_buffer, throw_on_error);
            }
        }

        /// <summary>
        /// Create a new file
        /// </summary>
        /// <param name="path">The path to the file</param>
        /// <param name="root">A root object to parse relative filenames</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="file_attributes">Attributes for the file</param>
        /// <param name="share_access">Share access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="disposition">Disposition when opening the file</param>
        /// <param name="ea_buffer">Extended Attributes buffer</param>
        /// <returns>The created/opened file object.</returns>
        public static NtFile Create(string path, NtObject root, FileAccessRights desired_access, FileAttributes file_attributes, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer)
        {
            return Create(path, root, desired_access, file_attributes, share_access, open_options, disposition, ea_buffer, true).Result;
        }

        /// <summary>
        /// Create a new file
        /// </summary>
        /// <param name="path">The path to the file</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="share_access">Share access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="disposition">Disposition when opening the file</param>
        /// <param name="ea_buffer">Extended Attributes buffer</param>
        /// <returns>The created/opened file object.</returns>
        public static NtFile Create(string path, FileAccessRights desired_access, FileShareMode share_access,
            FileOpenOptions open_options, FileDisposition disposition, EaBuffer ea_buffer)
        {
            return Create(path, null, desired_access, FileAttributes.Normal, share_access, open_options, disposition, ea_buffer);
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
        /// <param name="path">The path to the pipe file</param>
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
        public static NtResult<NtNamedPipeFile> CreateNamedPipe(string path, NtObject root, FileAccessRights desired_access,
            FileShareMode share_access, FileOpenOptions open_options, FileDisposition disposition, NamedPipeType pipe_type,
            NamedPipeReadMode read_mode, NamedPipeCompletionMode completion_mode, int maximum_instances, int input_quota,
            int output_quota, NtWaitTimeout default_timeout, bool throw_on_error)
        {
            using (ObjectAttributes obj_attributes = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return CreateNamedPipe(obj_attributes, desired_access, share_access, open_options, disposition, pipe_type,
                    read_mode, completion_mode, maximum_instances, input_quota, output_quota, default_timeout, throw_on_error);
            }
        }

        /// <summary>
        /// Create a new named pipe file
        /// </summary>
        /// <param name="path">The path to the pipe file</param>
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
        public static NtNamedPipeFile CreateNamedPipe(string path, NtObject root, FileAccessRights desired_access,
            FileShareMode share_access, FileOpenOptions open_options, FileDisposition disposition, NamedPipeType pipe_type,
            NamedPipeReadMode read_mode, NamedPipeCompletionMode completion_mode, int maximum_instances, int input_quota,
            int output_quota, NtWaitTimeout default_timeout)
        {
            return CreateNamedPipe(path, root, desired_access, share_access, open_options, disposition, pipe_type,
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
        /// <param name="default_timeout">Read Timeout.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The file instance for the mailslot.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtMailslotFile> CreateMailslot(ObjectAttributes obj_attributes, FileAccessRights desired_access,
            FileOpenOptions open_options, int maximum_message_size, int mailslot_quota,
            NtWaitTimeout default_timeout, bool throw_on_error)
        {
            IoStatus io_status = new IoStatus();
            LargeInteger timeout = default_timeout?.Timeout ?? new LargeInteger(-1);
            return NtSystemCalls.NtCreateMailslotFile(out SafeKernelObjectHandle handle, desired_access,
                obj_attributes, io_status, open_options, mailslot_quota, maximum_message_size, timeout)
                .CreateResult(throw_on_error, () => new NtMailslotFile(handle, io_status));
        }

        /// <summary>
        /// Create a new named mailslot file
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="mailslot_quota">Mailslot quota</param>
        /// <param name="maximum_message_size">Maximum message size (0 for any size)</param>
        /// <param name="default_timeout">Read timeout in MS (&lt;0 is infinite)</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The file instance for the mailslot.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtMailslotFile> CreateMailslot(ObjectAttributes obj_attributes, FileAccessRights desired_access,
            FileOpenOptions open_options, int maximum_message_size, int mailslot_quota,
            long default_timeout, bool throw_on_error)
        {
            return CreateMailslot(obj_attributes, desired_access, open_options,
                maximum_message_size, mailslot_quota, default_timeout >= 0 ? NtWaitTimeout.FromMilliseconds(default_timeout) : null, throw_on_error);
        }

        /// <summary>
        /// Create a new named mailslot file
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="mailslot_quota">Mailslot quota</param>
        /// <param name="maximum_message_size">Maximum message size (0 for any size)</param>
        /// <param name="default_timeout">Read timeout in MS ( &lt;0 is infinite)</param>
        /// <returns>The file instance for the mailslot.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtMailslotFile CreateMailslot(ObjectAttributes obj_attributes, FileAccessRights desired_access,
            FileOpenOptions open_options, int maximum_message_size, int mailslot_quota,
            long default_timeout)
        {
            return CreateMailslot(obj_attributes, desired_access, open_options,
                maximum_message_size, mailslot_quota, default_timeout, true).Result;
        }

        /// <summary>
        /// Create a new named mailslot file
        /// </summary>
        /// <param name="path">The path to the mailslot file</param>
        /// <param name="root">A root object to parse relative filenames</param>
        /// <param name="desired_access">Desired access for the file</param>
        /// <param name="open_options">Open options for file</param>
        /// <param name="mailslot_quota">Mailslot quota</param>
        /// <param name="maximum_message_size">Maximum message size (0 for any size)</param>
        /// <param name="default_timeout">Timeout in MS ( &lt;0 is infinite)</param>
        /// <returns>The file instance for the mailslot.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtMailslotFile CreateMailslot(string path, NtObject root, FileAccessRights desired_access,
            FileOpenOptions open_options, int maximum_message_size, int mailslot_quota,
            long default_timeout)
        {
            using (ObjectAttributes obj_attributes = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
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
        [Obsolete("Use FileIdValue")]
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
        [Obsolete("Use version of OpenFileById which accepts a long or GUID instead.")]
        public static NtResult<NtFile> OpenFileById(NtFile volume, string id,
            FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options, bool throw_on_error)
        {
            return OpenFileById(volume, NtFileUtils.StringToFileId(id), desired_access, share_access, open_options, throw_on_error);
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
        [Obsolete("Use version of OpenFileById which accepts a long or GUID instead.")]
        public static NtFile OpenFileById(NtFile volume, string id,
            FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options)
        {
            return OpenFileById(volume, id, desired_access, share_access, open_options, true).Result;
        }

        /// <summary>
        /// Open a file by its ID
        /// </summary>
        /// <param name="volume">A handle to the volume on which the file resides.</param>
        /// <param name="id">The file's ID. Can be a file reference number or an Object ID.</param>
        /// <param name="desired_access">The desired access for the file</param>
        /// <param name="share_access">File share access</param>
        /// <param name="open_options">Open options.</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The opened file object</returns>
        public static NtResult<NtFile> OpenFileById(NtFile volume, byte[] id,
            FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options, bool throw_on_error)
        {
            using (ObjectAttributes obja = ObjectAttributes.CreateWithRawName(id, AttributeFlags.CaseInsensitive, volume, null, null))
            {
                IoStatus iostatus = new IoStatus();
                return NtSystemCalls.NtOpenFile(out SafeKernelObjectHandle handle, desired_access, obja,
                    iostatus, share_access, open_options | FileOpenOptions.OpenByFileId)
                    .CreateResult(throw_on_error, () => new NtFile(handle, iostatus));
            }
        }

        /// <summary>
        /// Open a file by its ID
        /// </summary>
        /// <param name="volume">A handle to the volume on which the file resides.</param>
        /// <param name="id">The file's ID. Can be a file reference number or an Object ID.</param>
        /// <param name="desired_access">The desired access for the file</param>
        /// <param name="share_access">File share access</param>
        /// <param name="open_options">Open options.</param>
        /// <returns>The opened file object</returns>
        public static NtFile OpenFileById(NtFile volume, byte[] id,
            FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options)
        {
            return OpenFileById(volume, id, desired_access, share_access, open_options, true).Result;
        }

        /// <summary>
        /// Open a file by its object ID
        /// </summary>
        /// <param name="volume">A handle to the volume on which the file resides.</param>
        /// <param name="fileid">The file ID.</param>
        /// <param name="desired_access">The desired access for the file</param>
        /// <param name="share_access">File share access</param>
        /// <param name="open_options">Open options.</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The opened file object</returns>
        public static NtResult<NtFile> OpenFileById(NtFile volume, long fileid,
            FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options, bool throw_on_error)
        {
            return OpenFileById(volume, BitConverter.GetBytes(fileid), desired_access, share_access, open_options, throw_on_error);
        }

        /// <summary>
        /// Open a file by its file ID
        /// </summary>
        /// <param name="volume">A handle to the volume on which the file resides.</param>
        /// <param name="fileid">The file ID.</param>
        /// <param name="desired_access">The desired access for the file</param>
        /// <param name="share_access">File share access</param>
        /// <param name="open_options">Open options.</param>
        /// <returns>The opened file object</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtFile OpenFileById(NtFile volume, long fileid,
            FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options)
        {
            return OpenFileById(volume, fileid, desired_access, share_access, open_options, true).Result;
        }

        /// <summary>
        /// Open a file by its file ID
        /// </summary>
        /// <param name="volume_path">The path to the volume which contains the file.</param>
        /// <param name="fileid">The file ID.</param>
        /// <param name="desired_access">The desired access for the file</param>
        /// <param name="share_access">File share access</param>
        /// <param name="open_options">Open options.</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The opened file object</returns>
        public static NtResult<NtFile> OpenFileById(string volume_path, long fileid,
            FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options, bool throw_on_error)
        {
            return OpenFileById(null, NtFileUtils.GetFileIdPath(volume_path, fileid),
                desired_access, share_access, open_options, throw_on_error);
        }

        /// <summary>
        /// Open a file by its file ID
        /// </summary>
        /// <param name="volume_path">The path to the volume which contains the file.</param>
        /// <param name="fileid">The file ID.</param>
        /// <param name="desired_access">The desired access for the file</param>
        /// <param name="share_access">File share access</param>
        /// <param name="open_options">Open options.</param>
        /// <returns>The opened file object</returns>
        public static NtFile OpenFileById(string volume_path, long fileid,
            FileAccessRights desired_access, FileShareMode share_access, FileOpenOptions open_options)
        {
            return OpenFileById(volume_path, fileid, desired_access, share_access, open_options, true).Result;
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

        /// <summary>
        /// Query attributes of a file.
        /// </summary>
        /// <param name="object_attributes">The object attributes.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The file attributes.</returns>
        public static NtResult<FileInformation> QueryAttributes(ObjectAttributes object_attributes, bool throw_on_error)
        {
            return NtSystemCalls.NtQueryFullAttributesFile(object_attributes,
                out FileNetworkOpenInformation open_info).CreateResult(throw_on_error, () => new FileInformation(open_info));
        }

        /// <summary>
        /// Query attributes of a file.
        /// </summary>
        /// <param name="object_attributes">The object attributes.</param>
        /// <returns>The file attributes.</returns>
        public static FileInformation QueryAttributes(ObjectAttributes object_attributes)
        {
            return QueryAttributes(object_attributes, true).Result;
        }

        /// <summary>
        /// Query attributes of a file.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <param name="root">The root directory to parse from.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The file attributes.</returns>
        public static NtResult<FileInformation> QueryAttributes(string path, NtObject root, bool throw_on_error)
        {
            using (var obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return QueryAttributes(obja, throw_on_error);
            }
        }

        /// <summary>
        /// Query attributes of a file.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <param name="root">The root directory to parse from.</param>
        /// <returns>The file attributes.</returns>
        public static FileInformation QueryAttributes(string path, NtObject root)
        {
            return QueryAttributes(path, root, true).Result;
        }

        /// <summary>
        /// Query attributes of a file.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <returns>The file attributes.</returns>
        public static FileInformation QueryAttributes(string path)
        {
            return QueryAttributes(path, null);
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
        /// <param name="attributes">Flags for the object attributes.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtResult<NtFile> ReOpen(FileAccessRights desired_access, FileShareMode share_access, 
            FileOpenOptions open_options, AttributeFlags attributes, bool throw_on_error)
        {
            using (ObjectAttributes obj_attributes = new ObjectAttributes(string.Empty, attributes, this))
            {
                return Open(obj_attributes, desired_access, share_access, open_options, throw_on_error);
            }
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
            return ReOpen(desired_access, share_access, open_options, AttributeFlags.CaseInsensitive, throw_on_error);
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
        /// Specify file disposition.
        /// </summary>
        /// <param name="delete_file">True to set delete on close, false to clear delete on close.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <remarks>You can't prevent deletion if file opened with DeleteOnClose flag.</remarks>
        public NtStatus SetDisposition(bool delete_file, bool throw_on_error)
        {
            return Set(FileInformationClass.FileDispositionInformation,
                new FileDispositionInformation() { DeleteFile = delete_file }, throw_on_error);
        }

        /// <summary>
        /// Specify file disposition.
        /// </summary>
        /// <param name="delete_file">True to set delete on close, false to clear delete on close.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <remarks>You can't prevent deletion if file opened with DeleteOnClose flag.</remarks>
        public void SetDisposition(bool delete_file)
        {
            SetDisposition(delete_file, true);
        }

        /// <summary>
        /// Delete the file. Must have been opened with DELETE access.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus Delete(bool throw_on_error)
        {
            return SetDisposition(true, throw_on_error);
        }

        /// <summary>
        /// Delete the file. Must have been opened with DELETE access.
        /// </summary>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Delete()
        {
            Delete(true);
        }

        /// <summary>
        /// Set disposition on the file (extended Windows version).
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <param name="flags">Flags for SetDispositionEx call.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus SetDispositionEx(FileDispositionInformationExFlags flags, bool throw_on_error)
        {
            return Set(FileInformationClass.FileDispositionInformationEx,
                new FileDispositionInformationEx() { Flags = flags }, throw_on_error);
        }

        /// <summary>
        /// Set disposition on the file (extended Windows version).
        /// </summary>
        /// <param name="flags">Flags for SetDispositionEx call.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetDispositionEx(FileDispositionInformationExFlags flags)
        {
            SetDispositionEx(flags, true);
        }

        /// <summary>
        /// Delete the file (extended Windows version). Must have been opened with DELETE access.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <param name="flags">Flags for DeleteEx call.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus DeleteEx(FileDispositionInformationExFlags flags, bool throw_on_error)
        {
            return SetDispositionEx(flags, throw_on_error);
        }

        /// <summary>
        /// Delete the file (extended Windows version). Must have been opened with DELETE access.
        /// </summary>
        /// <param name="flags">Flags for DeleteEx call.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void DeleteEx(FileDispositionInformationExFlags flags)
        {
            DeleteEx(flags, true);
        }

        /// <summary>
        /// Create a new hardlink to this file.
        /// </summary>
        /// <param name="linkname">The target NT path.</param>
        /// <param name="root">The root directory if linkname is relative</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void CreateHardlink(string linkname, NtFile root)
        {
            DoLinkRename(FileInformationClass.FileLinkInformation, linkname, root, true, true);
        }

        /// <summary>
        /// Create a new hardlink to this file.
        /// </summary>
        /// <param name="linkname">The target absolute NT path.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void CreateHardlink(string linkname)
        {
            DoLinkRename(FileInformationClass.FileLinkInformation, linkname, null, true, true);
        }

        /// <summary>
        /// Create a new hardlink to this file.
        /// </summary>
        /// <param name="linkname">The target NT path.</param>
        /// <param name="root">The root directory if linkname is relative</param>
        /// <param name="replace_if_exists">If TRUE, replaces the target file if it exists. If FALSE, fails if the target file already exists.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus CreateHardlink(string linkname, NtObject root, bool replace_if_exists, bool throw_on_error)
        {
            return DoLinkRename(FileInformationClass.FileLinkInformation, linkname, root, replace_if_exists, throw_on_error);
        }

        /// <summary>
        /// Create a new hardlink to this file.
        /// </summary>
        /// <param name="linkname">The target NT path.</param>
        /// <param name="root">The root directory if linkname is relative</param>
        /// <param name="replace_if_exists">If TRUE, replaces the target file if it exists. If FALSE, fails if the target file already exists.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void CreateHardlink(string linkname, NtObject root, bool replace_if_exists)
        {
            CreateHardlink(linkname, root, replace_if_exists, true);
        }

        /// <summary>
        /// Create a new hardlink to this file.
        /// </summary>
        /// <param name="linkname">The target NT path.</param>
        /// <param name="root">The root directory if linkname is relative</param>
        /// <param name="flags">The flags associated to FileLinkInformationEx.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus CreateHardlinkEx(string linkname, NtObject root, FileRenameInformationExFlags flags, bool throw_on_error)
        {
            return DoLinkRenameEx(FileInformationClass.FileLinkInformationEx, linkname, root, flags, throw_on_error);
        }

        /// <summary>
        /// Create a new hardlink to this file.
        /// </summary>
        /// <param name="linkname">The target NT path.</param>
        /// <param name="root">The root directory if linkname is relative</param>
        /// <param name="flags">The flags associated to FileLinkInformationEx.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void CreateHardlinkEx(string linkname, NtObject root, FileRenameInformationExFlags flags)
        {
            CreateHardlinkEx(linkname, root, flags, true);
        }

        /// <summary>
        /// Rename file.
        /// </summary>
        /// <param name="new_name">The target NT path.</param>
        /// <param name="root">The root directory if new_name is relative</param>
        /// <param name="replace_if_exists">If TRUE, replaces the target file if it exists. If FALSE, fails if the target file already exists.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus Rename(string new_name, NtObject root, bool replace_if_exists, bool throw_on_error)
        {
            return DoLinkRename(FileInformationClass.FileRenameInformation, new_name, root, replace_if_exists, true);
        }

        /// <summary>
        /// Rename file.
        /// </summary>
        /// <param name="new_name">The target NT path.</param>
        /// <param name="root">The root directory if new_name is relative</param>
        /// <param name="replace_if_exists">If TRUE, replaces the target file if it exists. If FALSE, fails if the target file already exists.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Rename(string new_name, NtObject root, bool replace_if_exists)
        {
            DoLinkRename(FileInformationClass.FileRenameInformation, new_name, root, replace_if_exists, true);
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
            DoLinkRename(FileInformationClass.FileRenameInformation, new_name, null, replace_if_exists, true);
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
        /// <param name="root">The root directory if new_name is relative</param>
        /// <param name="flags">The flags associated to FileRenameInformationEx.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtStatus RenameEx(string new_name, NtObject root, FileRenameInformationExFlags flags, bool throw_on_error)
        {
            return DoLinkRenameEx(FileInformationClass.FileRenameInformationEx, new_name, root, flags, throw_on_error);
        }

        /// <summary>
        /// Rename (extended Windows version) this file with an absolute path.
        /// </summary>
        /// <param name="new_name">The target absolute NT path.</param>
        /// <param name="root">The root directory if new_name is relative</param>
        /// <param name="flags">The flags associated to FileRenameInformationEx.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void RenameEx(string new_name, NtObject root, FileRenameInformationExFlags flags)
        {
            RenameEx(new_name, root, flags, true);
        }

        /// <summary>
        /// Rename (extended Windows version) this file with an absolute path.
        /// </summary>
        /// <param name="new_name">The target absolute NT path.</param>
        /// <param name="flags">The flags associated to FileRenameInformationEx.</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void RenameEx(string new_name, FileRenameInformationExFlags flags)
        {
            RenameEx(new_name, null, flags);
        }

        /// <summary>
        /// Set an arbitrary reparse point.
        /// </summary>
        /// <param name="reparse">The reparse point data.</param>
        public void SetReparsePoint(ReparseBuffer reparse)
        {
            SetReparsePoint(reparse, true);
        }

        /// <summary>
        /// Set an arbitrary reparse point.
        /// </summary>
        /// <param name="reparse">The reparse point data.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetReparsePoint(ReparseBuffer reparse, bool throw_on_error)
        {
            return SetReparsePoint(reparse.ToByteArray(), throw_on_error);
        }

        /// <summary>
        /// Set an arbitrary reparse point as a raw byte array.
        /// </summary>
        /// <param name="reparse">The reparse point data as a byte array.</param>
        public void SetReparsePoint(byte[] reparse)
        {
            SetReparsePoint(reparse, true);
        }

        /// <summary>
        /// Set an arbitrary reparse point as a raw byte array.
        /// </summary>
        /// <param name="reparse">The reparse point data as a byte array.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetReparsePoint(byte[] reparse, bool throw_on_error)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(reparse))
            {
                return FsControl(NtWellKnownIoControlCodes.FSCTL_SET_REPARSE_POINT, buffer, null, throw_on_error).Status;
            }
        }

        /// <summary>
        /// Set an arbitrary reparse point.
        /// </summary>
        /// <param name="reparse">The reparse point data.</param>
        /// <param name="flags">Flags for the reparse buffer.</param>
        /// <param name="existing_tag">Existing tag to check against. If no check required use 0.</param>
        /// <param name="existing_guid">Existing Guid to check against. If no check requested use empty GUID.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetReparsePointEx(ReparseBuffer reparse, ReparseBufferExFlags flags, ReparseTag existing_tag, Guid existing_guid, bool throw_on_error)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(reparse.ToByteArray(flags, existing_tag, existing_guid)))
            {
                return FsControl(NtWellKnownIoControlCodes.FSCTL_SET_REPARSE_POINT_EX, buffer, null, throw_on_error).Status;
            }
        }

        /// <summary>
        /// Set an arbitrary reparse point.
        /// </summary>
        /// <param name="reparse">The reparse point data.</param>
        /// <param name="flags">Flags for the reparse buffer.</param>
        /// <param name="existing_tag">Existing tag to check against. If no check required use 0.</param>
        /// <param name="existing_guid">Existing Guid to check against. If no check requested use empty GUID.</param>
        public void SetReparsePointEx(ReparseBuffer reparse, ReparseBufferExFlags flags, ReparseTag existing_tag, Guid existing_guid)
        {
            SetReparsePointEx(reparse, flags, existing_tag, existing_guid, true);
        }

        /// <summary>
        /// Set an arbitrary reparse point.
        /// </summary>
        /// <param name="reparse">The reparse point data.</param>
        /// <param name="existing_tag">Existing tag to check against. If no check required use 0.</param>
        public void SetReparsePointEx(ReparseBuffer reparse, ReparseTag existing_tag)
        {
            SetReparsePointEx(reparse, ReparseBufferExFlags.None, existing_tag, Guid.Empty);
        }

        /// <summary>
        /// Set an arbitrary reparse point.
        /// </summary>
        /// <param name="reparse">The reparse point data.</param>>
        public void SetReparsePointEx(ReparseBuffer reparse)
        {
            SetReparsePointEx(reparse, 0, 0, Guid.Empty);
        }

        /// <summary>
        /// Set a mount point on the current file object.
        /// </summary>
        /// <param name="substitute_name">The substitute name to reparse to.</param>
        /// <param name="print_name">The print name to display (can be null).</param>
        public void SetMountPoint(string substitute_name, string print_name)
        {
            SetMountPoint(substitute_name, print_name, true);
        }

        /// <summary>
        /// Set a symlink on the current file object.
        /// </summary>
        /// <param name="substitute_name">The substitute name to reparse to.</param>
        /// <param name="print_name">The print name to display.</param>
        /// <param name="flags">Additional flags for the symlink.</param>
        public void SetSymlink(string substitute_name, string print_name, SymlinkReparseBufferFlags flags)
        {
            SetSymlink(substitute_name, print_name, flags, true);
        }

        /// <summary>
        /// Set a mount point on the current file object.
        /// </summary>
        /// <param name="substitute_name">The substitute name to reparse to.</param>
        /// <param name="print_name">The print name to display (can be null).</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetMountPoint(string substitute_name, string print_name, bool throw_on_error)
        {
            return SetReparsePoint(new MountPointReparseBuffer(substitute_name, print_name), throw_on_error);
        }

        /// <summary>
        /// Set a symlink on the current file object.
        /// </summary>
        /// <param name="substitute_name">The substitute name to reparse to.</param>
        /// <param name="print_name">The print name to display.</param>
        /// <param name="flags">Additional flags for the symlink.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetSymlink(string substitute_name, string print_name, SymlinkReparseBufferFlags flags, bool throw_on_error)
        {
            return SetReparsePoint(new SymlinkReparseBuffer(substitute_name, print_name, flags), throw_on_error);
        }

        /// <summary>
        /// Get the reparse point buffer for the file.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The reparse point buffer.</returns>
        public NtResult<ReparseBuffer> GetReparsePoint(bool throw_on_error)
        {
            return GetReparsePointRaw(throw_on_error).Map(ba => ReparseBuffer.FromByteArray(ba));
        }

        /// <summary>
        /// Get the reparse point buffer for the file.
        /// </summary>
        /// <returns>The reparse point buffer.</returns>
        public ReparseBuffer GetReparsePoint()
        {
            return ReparseBuffer.FromByteArray(GetReparsePointRaw());
        }

        /// <summary>
        /// Get the reparse point buffer for the file as a raw buffer.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The reparse point buffer.</returns>
        public NtResult<byte[]> GetReparsePointRaw(bool throw_on_error)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(16 * 1024))
            {
                return FsControl(NtWellKnownIoControlCodes.FSCTL_GET_REPARSE_POINT,
                    null, buffer, throw_on_error).Map(i => buffer.ReadBytes(i));
            }
        }

        /// <summary>
        /// Get the reparse point buffer for the file as a raw buffer.
        /// </summary>
        /// <returns>The reparse point buffer.</returns>
        public byte[] GetReparsePointRaw()
        {
            return GetReparsePointRaw(true).Result;
        }

        /// <summary>
        /// Delete the reparse point buffer
        /// </summary>
        /// <param name="tag">The reparse tag.</param>
        /// <returns>The NT status code.</returns>
        /// <param name="throw_on_error">True to throw on error.</param>
        public NtStatus DeleteReparsePoint(ReparseTag tag, bool throw_on_error)
        {
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(
                new OpaqueReparseBuffer(tag, new byte[0]).ToByteArray()))
            {
                return FsControl(NtWellKnownIoControlCodes.FSCTL_DELETE_REPARSE_POINT, buffer, null, throw_on_error).Status;
            }
        }

        /// <summary>
        /// Delete the reparse point buffer
        /// </summary>
        /// <param name="tag">The reparse tag.</param>
        public void DeleteReparsePoint(ReparseTag tag)
        {
            DeleteReparsePoint(tag, true);
        }

        /// <summary>
        /// Delete the reparse point buffer
        /// </summary>
        /// <returns>The original reparse buffer.</returns>
        /// <param name="throw_on_error">True to throw on error.</param>
        public NtResult<ReparseBuffer> DeleteReparsePoint(bool throw_on_error)
        {
            var reparse = GetReparsePoint(throw_on_error);
            if (!reparse.IsSuccess)
                return reparse;

            return DeleteReparsePoint(reparse.Result.Tag, false)
                .CreateResult(throw_on_error, () => reparse.Result);
        }

        /// <summary>
        /// Delete the reparse point buffer
        /// </summary>
        /// <returns>The original reparse buffer.</returns>
        public ReparseBuffer DeleteReparsePoint()
        {
            return DeleteReparsePoint(true).Result;
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
        /// <returns>The list of directory entries.</returns>
        public IEnumerable<FileDirectoryEntry> QueryDirectoryInfo()
        {
            return QueryDirectoryInfo(null, FileTypeMask.All);
        }

        /// <summary>
        /// Query a directory for files.
        /// </summary>
        /// <param name="file_mask">A file name mask (such as *.txt). Can be null.</param>
        /// <param name="type_mask">Indicate what entries to return.</param>
        /// <param name="include_flags">Specify what additional data to include in the directory entries.</param>
        /// <returns>The list of directory entries. You might need to cast the directories to the appropriate types if using include flags.</returns>
        public IEnumerable<FileDirectoryEntry> QueryDirectoryInfo(string file_mask, FileTypeMask type_mask, DirectoryEntryIncludeFlags include_flags)
        {
            bool placeholders = include_flags.HasFlagSet(DirectoryEntryIncludeFlags.Placeholders);
            include_flags &= ~DirectoryEntryIncludeFlags.Placeholders;

            switch (include_flags)
            {
                case DirectoryEntryIncludeFlags.Default:
                    return QueryDirectoryInfo<FileDirectoryInformation, FileDirectoryEntry>(FileInformationClass.FileDirectoryInformation,
                    file_mask, type_mask, placeholders);
                case DirectoryEntryIncludeFlags.FileId:
                    return QueryDirectoryInfo<FileIdFullDirectoryInformation, FileIdDirectoryEntry>(FileInformationClass.FileIdFullDirectoryInformation,
                        file_mask, type_mask, placeholders);
                case DirectoryEntryIncludeFlags.ShortName:
                    return QueryDirectoryInfo<FileBothDirectoryInformation, FileBothDirectoryEntry>(FileInformationClass.FileBothDirectoryInformation,
                        file_mask, type_mask, placeholders);
                case DirectoryEntryIncludeFlags.FileId | DirectoryEntryIncludeFlags.ShortName:
                    return QueryDirectoryInfo<FileIdBothDirectoryInformation, FileIdBothDirectoryEntry>(FileInformationClass.FileIdBothDirectoryInformation,
                        file_mask, type_mask, placeholders);
                default:
                    throw new ArgumentException("Invalid include flags", nameof(include_flags));
            }
        }

        /// <summary>
        /// Query a directory for files.
        /// </summary>
        /// <param name="file_mask">A file name mask (such as *.txt). Can be null.</param>
        /// <param name="type_mask">Indicate what entries to return.</param>
        /// <returns>The list of directory entries.</returns>
        public IEnumerable<FileDirectoryEntry> QueryDirectoryInfo(string file_mask, FileTypeMask type_mask)
        {
            return QueryDirectoryInfo(file_mask, type_mask, DirectoryEntryIncludeFlags.Default);
        }

        /// <summary>
        /// Query a directory for files with file ID.
        /// </summary>
        /// <param name="file_mask">A file name mask (such as *.txt). Can be null.</param>
        /// <param name="type_mask">Indicate what entries to return.</param>
        /// <param name="with_placeholders">Return placeholder parent and current directory entries.</param>
        /// <returns>The list of directory entries.</returns>
        public IEnumerable<FileIdDirectoryEntry> QueryFileIdDirectoryInfo(string file_mask, FileTypeMask type_mask, bool with_placeholders)
        {
            return QueryDirectoryInfo<FileIdFullDirectoryInformation, FileIdDirectoryEntry>(FileInformationClass.FileDirectoryInformation,
                file_mask, type_mask, with_placeholders);
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
            return RunFileCallSync(r => NtSystemCalls.NtReadFile(Handle, r.EventHandle, IntPtr.Zero,
                    IntPtr.Zero, r.IoStatusBuffer, buffer, 
                    buffer.GetLength(), position.ToLargeInteger(), IntPtr.Zero), throw_on_error)
                    .Map(r => r.Information32);
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
        /// Read data from a file with a length over a scatter set of pages.
        /// </summary>
        /// <param name="pages">List of pages to read into. These pages must be Page Size aligned.</param>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The length of bytes read.</returns>
        public NtResult<int> ReadScatter(IEnumerable<long> pages, int length, long position, bool throw_on_error)
        {
            FileSegmentElement[] segments = PageListToSegments(pages);

            return RunFileCallSync(r => NtSystemCalls.NtReadFileScatter(Handle, r.EventHandle, IntPtr.Zero,
                    IntPtr.Zero, r.IoStatusBuffer, segments, length, new LargeInteger(position), IntPtr.Zero),
                    throw_on_error).Map(s => s.Information32);
        }

        /// <summary>
        /// Read data from a file with a length over a scatter set of pages.
        /// </summary>
        /// <param name="pages">List of pages to read into. These pages must be Page Size aligned.</param>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read.</param>
        /// <returns>The length of bytes read.</returns>
        public int ReadScatter(IEnumerable<long> pages, int length, long position)
        {
            return ReadScatter(pages, length, position, true).Result;
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
        public Task<int> ReadAsync(SafeBuffer buffer, long position, CancellationToken token)
        {
            return ReadAsync(buffer, position, token, true).UnwrapNtResultAsync();
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
        public Task<byte[]> ReadAsync(int length, long position, CancellationToken token)
        {
            return ReadAsync(length, position, token, true).UnwrapNtResultAsync();
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
        /// Read data from a file with a length and position asynchronously.
        /// </summary>
        /// <param name="pages">List of pages to read into. These pages must be Page Size aligned.</param>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The length of bytes read into the buffer.</returns>
        public async Task<NtResult<int>> ReadScatterAsync(IEnumerable<long> pages, int length, long position, CancellationToken token, bool throw_on_error)
        {
            FileSegmentElement[] segments = PageListToSegments(pages);

            var status = await RunFileCallAsync(result => NtSystemCalls.NtReadFileScatter(Handle, result.EventHandle, IntPtr.Zero,
                        IntPtr.Zero, result.IoStatusBuffer, segments, length, new LargeInteger(position), IntPtr.Zero), token, throw_on_error);
            return status.Map(r => r.Information32);
        }

        /// <summary>
        /// Read data from a file with a length and position asynchronously.
        /// </summary>
        /// <param name="pages">List of pages to read into. These pages must be Page Size aligned.</param>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The length of bytes read into the buffer.</returns>
        public Task<NtResult<int>> ReadScatterAsync(IEnumerable<long> pages, int length, long position, bool throw_on_error)
        {
            return ReadScatterAsync(pages, length, position, CancellationToken.None, throw_on_error);
        }

        /// <summary>
        /// Read data from a file with a length and position asynchronously.
        /// </summary>
        /// <param name="pages">List of pages to read into. These pages must be Page Size aligned.</param>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <returns>The length of bytes read into the buffer.</returns>
        public Task<int> ReadScatterAsync(IEnumerable<long> pages, int length, long position, CancellationToken token)
        {
            return ReadScatterAsync(pages, length, position, token, true).UnwrapNtResultAsync();
        }

        /// <summary>
        /// Read data from a file with a length and position asynchronously.
        /// </summary>
        /// <param name="pages">List of pages to read into. These pages must be Page Size aligned.</param>
        /// <param name="length">The length of the read</param>
        /// <param name="position">The position in the file to read.</param>
        /// <returns>The length of bytes read into the buffer.</returns>
        public Task<int> ReadScatterAsync(IEnumerable<long> pages, int length, long position)
        {
            return ReadScatterAsync(pages, length, position, CancellationToken.None);
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
        public Task<int> WriteAsync(SafeBuffer data, long position, CancellationToken token)
        {
            return WriteAsync(data, position, token, true).UnwrapNtResultAsync();
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
            return WriteAsync(data, position, token, true).UnwrapNtResultAsync();
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
        /// Write data to a file at a specific position.
        /// </summary>
        /// <param name="data">The data to write</param>
        /// <param name="position">The position to write to. Optional</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The number of bytes written.</returns>
        public NtResult<int> Write(SafeBuffer data, long? position, bool throw_on_error)
        {
            return RunFileCallSync(r => NtSystemCalls.NtWriteFile(Handle, r.EventHandle, IntPtr.Zero,
                    IntPtr.Zero, r.IoStatusBuffer, data, data.GetLength(), position.ToLargeInteger(), IntPtr.Zero),
                    throw_on_error).Map(s => s.Information32);
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
        /// Write data to a file at a specific position gathered from a list of pages.
        /// </summary>
        /// <param name="pages">List of pages to write. These pages must be page size aligned.</param>
        /// <param name="length">The length of the write.</param>
        /// <param name="position">The position to write to.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The number of bytes written.</returns>
        public NtResult<int> WriteGather(IEnumerable<long> pages, int length, long position, bool throw_on_error)
        {
            var segments = PageListToSegments(pages);
            return RunFileCallSync(r => NtSystemCalls.NtWriteFileGather(Handle, r.EventHandle, IntPtr.Zero,
                    IntPtr.Zero, r.IoStatusBuffer, segments, length, new LargeInteger(position), IntPtr.Zero),
                    throw_on_error).Map(s => s.Information32);
        }

        /// <summary>
        /// Write data to a file at a specific position gathered from a list of pages.
        /// </summary>
        /// <param name="pages">List of pages to write. These pages must be page size aligned.</param>
        /// <param name="length">The length of the write.</param>
        /// <param name="position">The position to write to.</param>
        /// <returns>The number of bytes written.</returns>
        public int WriteGather(IEnumerable<long> pages, int length, long position)
        {
            return WriteGather(pages, length, position, true).Result;
        }

        /// <summary>
        /// Write data to a file at a specific position asynchronously from a list of pages.
        /// </summary>
        /// <param name="pages">List of pages to write. These pages must be page size aligned.</param>
        /// <param name="length">The length of the write.</param>
        /// <param name="position">The position to write to.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The number of bytes written</returns>
        public async Task<NtResult<int>> WriteGatherAsync(IEnumerable<long> pages, int length, long position, CancellationToken token, bool throw_on_error)
        {
            var segments = PageListToSegments(pages);
            var result = await RunFileCallAsync(r => NtSystemCalls.NtWriteFileGather(Handle, r.EventHandle, IntPtr.Zero,
                        IntPtr.Zero, r.IoStatusBuffer, segments, length, new LargeInteger(position), IntPtr.Zero), token,
                        throw_on_error);
            return result.Map(r => r.Information32);
        }

        /// <summary>
        /// Write data to a file at a specific position asynchronously from a list of pages.
        /// </summary>
        /// <param name="pages">List of pages to write. These pages must be page size aligned.</param>
        /// <param name="length">The length of the write.</param>
        /// <param name="position">The position to write to.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The number of bytes written</returns>
        public Task<NtResult<int>> WriteGatherAsync(IEnumerable<long> pages, int length, long position, bool throw_on_error)
        {
            return WriteGatherAsync(pages, length, position, CancellationToken.None, throw_on_error);
        }

        /// <summary>
        /// Write data to a file at a specific position asynchronously from a list of pages.
        /// </summary>
        /// <param name="pages">List of pages to write. These pages must be page size aligned.</param>
        /// <param name="length">The length of the write.</param>
        /// <param name="position">The position to write to.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <returns>The number of bytes written</returns>
        public Task<int> WriteGatherAsync(IEnumerable<long> pages, int length, long position, CancellationToken token)
        {
            return WriteGatherAsync(pages, length, position, token, true).UnwrapNtResultAsync();
        }

        /// <summary>
        /// Write data to a file at a specific position asynchronously from a list of pages.
        /// </summary>
        /// <param name="pages">List of pages to write. These pages must be page size aligned.</param>
        /// <param name="length">The length of the write.</param>
        /// <param name="position">The position to write to.</param>
        /// <returns>The number of bytes written</returns>
        public Task<int> WriteGatherAsync(IEnumerable<long> pages, int length, long position)
        {
            return WriteGatherAsync(pages, length, position, CancellationToken.None);
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
            return RunFileCallSync(r => NtSystemCalls.NtLockFile(Handle, r.EventHandle, IntPtr.Zero,
                    IntPtr.Zero, r.IoStatusBuffer, new LargeInteger(offset),
                    new LargeInteger(size), 0, fail_immediately, exclusive), throw_on_error).Status;
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
            return Win32Utils.GetWin32PathName(this, flags, throw_on_error);
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="level">The level of oplock to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The oplock response level.</returns>
        public NtResult<OplockResponseLevel> RequestOplock(OplockRequestLevel level, bool throw_on_error)
        {
            return FsControl(GetOplockFsctl(level), null, null, throw_on_error).Map(r => (OplockResponseLevel)r);
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="level">The level of oplock to set.</param>
        /// <returns>The oplock response level.</returns>
        public OplockResponseLevel RequestOplock(OplockRequestLevel level)
        {
            return RequestOplock(level, true).Result;
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="level">The level of oplock to set.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The oplock response level.</returns>
        public Task<NtResult<OplockResponseLevel>> RequestOplockAsync(OplockRequestLevel level, CancellationToken token, bool throw_on_error)
        {
            return FsControlAsync(GetOplockFsctl(level), null, null, token, throw_on_error).MapAsync(r => (OplockResponseLevel)r);
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="level">The level of oplock to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The oplock response level.</returns>
        public Task<NtResult<OplockResponseLevel>> RequestOplockAsync(OplockRequestLevel level, bool throw_on_error)
        {
            return RequestOplockAsync(level, CancellationToken.None, true);
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="level">The level of oplock to set.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <returns>The oplock response level.</returns>
        public Task<OplockResponseLevel> RequestOplockAsync(OplockRequestLevel level, CancellationToken token)
        {
            return RequestOplockAsync(level, token, true).UnwrapNtResultAsync();
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="level">The level of oplock to set.</param>
        /// <returns>The oplock response level.</returns>
        public Task<OplockResponseLevel> RequestOplockAsync(OplockRequestLevel level)
        {
            return RequestOplockAsync(level, CancellationToken.None);
        }

        /// <summary>
        /// Acknowledge an oplock break.
        /// </summary>
        /// <param name="level">The acknowledgment level.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <remarks>Oplock break acknowledgement returns STATUS_PENDING.</remarks>
        public NtStatus AcknowledgeOplock(OplockAcknowledgeLevel level, bool throw_on_error)
        {
            using (var io_status = new SafeIoStatusBuffer())
            {
                return NtSystemCalls.NtFsControlFile(Handle, SafeKernelObjectHandle.Null, IntPtr.Zero, IntPtr.Zero, io_status,
                    GetOplockAckFsctl(level).ToInt32(), IntPtr.Zero, 0, IntPtr.Zero, 0).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Acknowledge an oplock break.
        /// </summary>
        /// <param name="level">The acknowledgment level.</param>
        public void AcknowledgeOplock(OplockAcknowledgeLevel level)
        {
            AcknowledgeOplock(level, true);
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock cache level.</param>
        /// <param name="flags">Specify additional flags for the request.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the oplock request.</returns>
        public NtResult<RequestOplockOutputBuffer> RequestOplockLease(OplockLevelCache requested_oplock_level, RequestOplockInputFlag flags, bool throw_on_error)
        {
            using (var input_buffer = new RequestOplockInputBuffer(requested_oplock_level, flags).ToBuffer())
            {
                using (var output_buffer = new SafeStructureInOutBuffer<RequestOplockOutputBuffer>())
                {
                    var result = FsControl(NtWellKnownIoControlCodes.FSCTL_REQUEST_OPLOCK, input_buffer, output_buffer, throw_on_error);
                    if (!result.IsSuccess)
                    {
                        return result.Status.CreateResultFromError<RequestOplockOutputBuffer>(throw_on_error);
                    }
                    if (result.Result != output_buffer.Length)
                    {
                        return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<RequestOplockOutputBuffer>(throw_on_error);
                    }
                    return result.Map(i => output_buffer.Result);
                }
            }
        }

        /// <summary>
        /// Oplock the file with a specific level.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock cache level.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the oplock request.</returns>
        public NtResult<RequestOplockOutputBuffer> RequestOplockLease(OplockLevelCache requested_oplock_level, bool throw_on_error)
        {
            return RequestOplockLease(requested_oplock_level, RequestOplockInputFlag.Request, throw_on_error);
        }

        /// <summary>
        /// Oplock the file with a specific level and flags.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock level.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <param name="flags">Specify additional flags for the request.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The request of the oplock request.</returns>
        public async Task<NtResult<RequestOplockOutputBuffer>> RequestOplockLeaseAsync(OplockLevelCache requested_oplock_level,
            RequestOplockInputFlag flags, CancellationToken token, bool throw_on_error)
        {
            using (var input_buffer = new RequestOplockInputBuffer(requested_oplock_level, flags).ToBuffer())
            {
                using (var output_buffer = new SafeStructureInOutBuffer<RequestOplockOutputBuffer>())
                {
                    var result = await FsControlAsync(NtWellKnownIoControlCodes.FSCTL_REQUEST_OPLOCK,
                        input_buffer, output_buffer, token, throw_on_error);
                    if (!result.IsSuccess)
                    {
                        return result.Status.CreateResultFromError<RequestOplockOutputBuffer>(throw_on_error);
                    }
                    if (result.Result != output_buffer.Length)
                    {
                        return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<RequestOplockOutputBuffer>(throw_on_error);
                    }
                    return result.Map(i => output_buffer.Result);
                }
            }
        }

        /// <summary>
        /// Oplock the file with a specific level and flags.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock level.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The request of the oplock request.</returns>
        public Task<NtResult<RequestOplockOutputBuffer>> RequestOplockLeaseAsync(OplockLevelCache requested_oplock_level,
             CancellationToken token, bool throw_on_error)
        {
            return RequestOplockLeaseAsync(requested_oplock_level, RequestOplockInputFlag.Request, token, throw_on_error);
        }

        /// <summary>
        /// Oplock the file with a specific lease level and flags.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock lease level.</param>
        /// <param name="flags">Specify additional flags for the request.</param>
        /// <returns>The result of the oplock request.</returns>
        public RequestOplockOutputBuffer RequestOplockLease(OplockLevelCache requested_oplock_level, RequestOplockInputFlag flags)
        {
            return RequestOplockLease(requested_oplock_level, flags, true).Result;
        }

        /// <summary>
        /// Oplock the file with a specific lease level and flags.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock lease level.</param>
        /// <returns>The result of the oplock request.</returns>
        public RequestOplockOutputBuffer RequestOplockLease(OplockLevelCache requested_oplock_level)
        {
            return RequestOplockLease(requested_oplock_level, RequestOplockInputFlag.Request);
        }

        /// <summary>
        /// Oplock the file with a specific level and flags.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock level.</param>
        /// <param name="flags">Specify additional flags for the request.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <returns>The request of the oplock request.</returns>
        public Task<RequestOplockOutputBuffer> RequestOplockLeaseAsync(OplockLevelCache requested_oplock_level, RequestOplockInputFlag flags, CancellationToken token)
        {
            return RequestOplockLeaseAsync(requested_oplock_level, flags, token, true).UnwrapNtResultAsync();
        }

        /// <summary>
        /// Oplock the file with a specific level and flags.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock level.</param>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <returns>The request of the oplock request.</returns>
        public Task<RequestOplockOutputBuffer> RequestOplockLeaseAsync(OplockLevelCache requested_oplock_level, CancellationToken token)
        {
            return RequestOplockLeaseAsync(requested_oplock_level, RequestOplockInputFlag.Request, token);
        }

        /// <summary>
        /// Oplock the file with a specific level and flags.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock level.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The request of the oplock request.</returns>
        public Task<NtResult<RequestOplockOutputBuffer>> RequestOplockLeaseAsync(OplockLevelCache requested_oplock_level, bool throw_on_error)
        {
            return RequestOplockLeaseAsync(requested_oplock_level, RequestOplockInputFlag.Request, CancellationToken.None, throw_on_error);
        }

        /// <summary>
        /// Oplock the file with a specific level and flags.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock level.</param>
        /// <returns>The response of the oplock request.</returns>
        public Task<RequestOplockOutputBuffer> RequestOplockLeaseAsync(OplockLevelCache requested_oplock_level)
        {
            return RequestOplockLeaseAsync(requested_oplock_level, true).UnwrapNtResultAsync();
        }

        /// <summary>
        /// Oplock the file with a specific level and flags.
        /// </summary>
        /// <param name="requested_oplock_level">The oplock level.</param>
        /// <param name="flags">Specify additional flags for the request.</param>
        /// <returns>The response of the oplock request.</returns>
        public Task<RequestOplockOutputBuffer> RequestOplockLeaseAsync(OplockLevelCache requested_oplock_level, RequestOplockInputFlag flags)
        {
            return RequestOplockLeaseAsync(requested_oplock_level, flags, CancellationToken.None, true).UnwrapNtResultAsync();
        }

        /// <summary>
        /// Acknowledge a lease oplock started with RequestOplockLease.
        /// </summary>
        /// <param name="complete_on_close">True to complete acknowledgement on close.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <remarks>This breaks to None. If you want to request the new oplock level then request a new oplock.</remarks>
        public NtStatus AcknowledgeOplockLease(bool complete_on_close, bool throw_on_error)
        {
            using (var input_buffer = new RequestOplockInputBuffer(OplockLevelCache.None,
                complete_on_close ? RequestOplockInputFlag.CompleteAckOnClose : RequestOplockInputFlag.Ack).ToBuffer())
            {
                using (var output_buffer = new SafeStructureInOutBuffer<RequestOplockOutputBuffer>())
                {
                    using (var io_status = new SafeIoStatusBuffer())
                    {
                        var status = NtSystemCalls.NtFsControlFile(Handle, SafeKernelObjectHandle.Null, IntPtr.Zero, IntPtr.Zero,
                            io_status, NtWellKnownIoControlCodes.FSCTL_REQUEST_OPLOCK.ToInt32(), input_buffer.DangerousGetHandle(), input_buffer.Length,
                            output_buffer.DangerousGetHandle(), output_buffer.Length).ToNtException(throw_on_error);
                        if (status == NtStatus.STATUS_PENDING)
                        {
                            // Cancel any pending IO if the result was pending, just to be sure.
                            CancelIo();
                        }
                        return status;
                    }
                }
            }
        }

        /// <summary>
        /// Acknowledge a lease oplock started with RequestOplockLease.
        /// </summary>
        /// <param name="complete_on_close">True to complete acknowledgement on close.</param>
        public void AcknowledgeOplockLease(bool complete_on_close)
        {
            AcknowledgeOplockLease(complete_on_close, true);
        }

        /// <summary>
        /// Acknowledge a lease oplock started with RequestOplockLease.
        /// </summary>
        public void AcknowledgeOplockLease()
        {
            AcknowledgeOplockLease(false);
        }

        /// <summary>
        /// Oplock the file exclusively (no other users can access the file).
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The oplock response level.</returns>
        public NtResult<OplockResponseLevel> OplockExclusive(bool throw_on_error)
        {
            return RequestOplock(OplockRequestLevel.Level1, throw_on_error);
        }

        /// <summary>
        /// Oplock the file exclusively (no other users can access the file).
        /// </summary>
        /// <returns>The oplock response level.</returns>
        public OplockResponseLevel OplockExclusive()
        {
            return RequestOplock(OplockRequestLevel.Level1);
        }

        /// <summary>
        /// Oplock the file exclusively (no other users can access the file).
        /// </summary>
        /// <param name="token">Cancellation token to cancel async operation.</param>
        /// <returns>The oplock response level.</returns>
        public Task<OplockResponseLevel> OplockExclusiveAsync(CancellationToken token)
        {
            return RequestOplockAsync(OplockRequestLevel.Level1, token);
        }

        /// <summary>
        /// Oplock the file exclusively (no other users can access the file).
        /// </summary>
        /// <returns>The oplock response level.</returns>
        public Task<OplockResponseLevel> OplockExclusiveAsync()
        {
            return OplockExclusiveAsync(CancellationToken.None);
        }

        /// <summary>
        /// Wait for an oplock break to complete.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus NotifyOplockBreak(bool throw_on_error)
        {
            return FsControl(NtWellKnownIoControlCodes.FSCTL_OPLOCK_BREAK_NOTIFY, null, null, throw_on_error).Status;
        }

        /// <summary>
        /// Wait for an oplock break to complete.
        /// </summary>
        /// <returns>The NT status code.</returns>
        public void NotifyOplockBreak()
        {
            NotifyOplockBreak(true);
        }

        /// <summary>
        /// Wait for an oplock break to complete.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public Task<NtStatus> NotifyOplockBreakAsync(bool throw_on_error)
        {
            return FsControlAsync(NtWellKnownIoControlCodes.FSCTL_OPLOCK_BREAK_NOTIFY, null, null, throw_on_error).UnwrapNtStatusAsync();
        }

        /// <summary>
        /// Wait for an oplock break to complete.
        /// </summary>
        /// <returns>The NT status code.</returns>
        public Task NotifyOplockBreakAsync()
        {
            return NotifyOplockBreakAsync(true);
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
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The extended attributes, empty if no extended attributes.</returns>
        public NtResult<EaBuffer> GetEa(bool throw_on_error)
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
                    return new EaBuffer(buffer).CreateResult();
                }
                else if (status == NtStatus.STATUS_NO_EAS_ON_FILE)
                {
                    return new EaBuffer().CreateResult();
                }
                else
                {
                    return status.CreateResultFromError<EaBuffer>(throw_on_error);
                }
            }
        }

        /// <summary>
        /// Get the extended attributes of a file.
        /// </summary>
        /// <returns>The extended attributes, empty if no extended attributes.</returns>
        public EaBuffer GetEa()
        {
            return GetEa(true).Result;
        }

        /// <summary>
        /// Set the extended attributes for a file.
        /// </summary>
        /// <param name="ea">The EA buffer to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <remarks>This will add entries if they no longer exist, 
        /// remove entries if the data is empty or update existing entires.</remarks>
        public NtStatus SetEa(EaBuffer ea, bool throw_on_error)
        {
            byte[] ea_buffer = ea.ToByteArray();
            IoStatus io_status = new IoStatus();
            return NtSystemCalls.NtSetEaFile(Handle, io_status, ea_buffer, ea_buffer.Length).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Set the extended attributes for a file.
        /// </summary>
        /// <param name="ea">The EA buffer to set.</param>
        /// <remarks>This will add entries if they no longer exist, 
        /// remove entries if the data is empty or update existing entires.</remarks>
        public void SetEa(EaBuffer ea)
        {
            SetEa(ea, true);
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
        public NtResult<CachedSigningLevel> GetCachedSigningLevel(bool throw_on_error)
        {
            return NtSecurity.GetCachedSigningLevel(Handle, throw_on_error);
        }

        /// <summary>
        /// Get the cached signing level for a file.
        /// </summary>
        /// <returns>The cached signing level.</returns>
        public CachedSigningLevel GetCachedSigningLevel()
        {
            return GetCachedSigningLevel(true).Result;
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
            SetCachedSigningLevel(flags, signing_level, null, catalog_path);
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
            SetCachedSigningLevel(flags, signing_level, files, catalog_path, true);
        }

        /// <summary>
        /// Set the cached signing level for a file.
        /// </summary>
        /// <param name="flags">Flags to set for the cache.</param>
        /// <param name="signing_level">The signing level to cache</param>
        /// <param name="files">Files for signature.</param>
        /// <param name="catalog_path">Optional directory path to look for catalog files.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        public NtStatus SetCachedSigningLevel(int flags, SigningLevel signing_level, IEnumerable<NtFile> files, string catalog_path, bool throw_on_error)
        {
            if (files == null)
            {
                files = new NtFile[] { this };
            }
            return NtSecurity.SetCachedSigningLevel(Handle, flags, signing_level, files.Select(f => f.Handle), catalog_path, throw_on_error);
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
                FileLinksInformation info = new FileLinksInformation
                {
                    BytesNeeded = size
                };

                using (var buffer = new SafeStructureInOutBuffer<FileLinksInformation>(info, size, true))
                {
                    IoStatus io_status = new IoStatus();
                    NtStatus status = QueryInformation(FileInformationClass.FileHardLinkInformation, buffer, out int length);
                    if (status == NtStatus.STATUS_BUFFER_OVERFLOW)
                    {
                        size *= 2;
                        continue;
                    }

                    status.ToNtException();
                    buffer.Initialize((ulong)length);
                    
                    info = buffer.Result;

                    int ofs = 0;

                    for (int i = 0; i < info.EntriesReturned; ++i)
                    {
                        var entry_buffer = buffer.Data.GetStructAtOffset<FileLinkEntryInformation>(ofs);
                        var entry = entry_buffer.Result;
                        string parent_path = string.Empty;
                        string win32_path = string.Empty;

                        using (var parent = OpenFileById(this, entry.ParentFileId,
                            FileAccessRights.ReadAttributes, FileShareMode.None, FileOpenOptions.None, false))
                        {
                            if (parent.IsSuccess)
                            {
                                parent_path = parent.Result.FullPath;
                                win32_path = parent.Result.GetWin32PathName(Win32PathNameFlags.None, false).GetResultOrDefault(string.Empty);
                            }
                        }

                        yield return new FileLinkEntry(entry_buffer, parent_path, win32_path);

                        if (entry.NextEntryOffset == 0)
                        {
                            break;
                        }
                        ofs += entry.NextEntryOffset;
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
            SetDynamicCodeTrust(true);
        }

        /// <summary>
        /// Set a file is trusted for dynamic code.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS4)]
        public NtStatus SetDynamicCodeTrust(bool throw_on_error)
        {
            return NtSystemInfo.SetDynamicCodeTrust(Handle).ToNtException(throw_on_error);
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
        /// Get full change notifications. Will pick ex version if available and revert to old format if not.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <param name="timeout">Wait timeout.</param>
        /// <returns>The list of changes.</returns>
        public NtResult<IEnumerable<DirectoryChangeNotification>> GetChangeNotificationFull(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree,
            NtWaitTimeout timeout, bool throw_on_error)
        {
            if (NtObjectUtils.SupportedVersion >= SupportedVersion.Windows10_RS3)
            {
                return GetChangeNotificationEx(completion_filter, watch_subtree, 
                    timeout, throw_on_error).Map(n => n.Cast<DirectoryChangeNotification>());
            }
            return GetChangeNotification(completion_filter, watch_subtree, timeout, throw_on_error);
        }

        /// <summary>
        /// Get full change notifications. Will pick ex version if available and revert to old format if not.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="timeout">Wait timeout.</param>
        /// <returns>The list of changes.</returns>
        public IEnumerable<DirectoryChangeNotification> GetChangeNotificationFull(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree,
            NtWaitTimeout timeout)
        {
            return GetChangeNotificationFull(completion_filter, watch_subtree, timeout, true).Result;
        }

        /// <summary>
        /// Get full change notifications asynchronously. Will pick ex version if available and revert to old format if not.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <param name="token">Cancellation token.</param>
        /// <returns>The list of changes.</returns>
        public Task<NtResult<IEnumerable<DirectoryChangeNotification>>> GetChangeNotificationFullAsync(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree, CancellationToken token, bool throw_on_error)
        {
            if (NtObjectUtils.SupportedVersion >= SupportedVersion.Windows10_RS3)
            {
                return GetChangeNotificationExAsync(completion_filter, watch_subtree, token, 
                    throw_on_error).MapAsync(s => s.Cast<DirectoryChangeNotification>());
            }
            return GetChangeNotificationAsync(completion_filter, watch_subtree, token, throw_on_error);
        }

        /// <summary>
        /// Get full change notifications asynchronously. Will pick ex version if available and revert to old format if not.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="token">Cancellation token.</param>
        /// <returns>The list of changes.</returns>
        public async Task<IEnumerable<DirectoryChangeNotification>> GetChangeNotificationFullAsync(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree, CancellationToken token)
        {
            var result = await GetChangeNotificationFullAsync(completion_filter, watch_subtree, token, true);
            return result.Result;
        }

        /// <summary>
        /// Get full change notifications asynchronously. Will pick ex version if available and revert to old format if not.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <returns>The list of changes.</returns>
        public Task<IEnumerable<DirectoryChangeNotification>> GetChangeNotificationFullAsync(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree)
        {
            return GetChangeNotificationFullAsync(completion_filter, watch_subtree, CancellationToken.None);
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <param name="timeout">Wait timeout.</param>
        /// <returns>The list of changes.</returns>
        public NtResult<IEnumerable<DirectoryChangeNotification>> GetChangeNotification(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree,
            NtWaitTimeout timeout, bool throw_on_error)
        {
            using (var buffer = new SafeHGlobalBuffer(ChangeNotificationBufferSize))
            {
                return RunFileCallSync(r => NtSystemCalls.NtNotifyChangeDirectoryFile(
                        Handle, r.EventHandle, IntPtr.Zero, IntPtr.Zero, r.IoStatusBuffer,
                        buffer, buffer.Length, completion_filter, watch_subtree), timeout, throw_on_error)
                    .Map((t, s) => t == NtStatus.STATUS_SUCCESS ? ReadNotifications(buffer, s) : new DirectoryChangeNotification[0]);
            }
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of changes.</returns>
        public NtResult<IEnumerable<DirectoryChangeNotification>> GetChangeNotification(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree, bool throw_on_error)
        {
            return GetChangeNotification(completion_filter, watch_subtree, NtWaitTimeout.Infinite, throw_on_error);
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="timeout">Wait timeout.</param>
        /// <returns>The list of changes.</returns>
        public IEnumerable<DirectoryChangeNotification> GetChangeNotification(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree,
            NtWaitTimeout timeout)
        {
            return GetChangeNotification(completion_filter, watch_subtree, timeout, true).Result;
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <returns>The list of changes.</returns>
        public IEnumerable<DirectoryChangeNotification> GetChangeNotification(DirectoryChangeNotifyFilter completion_filter, bool watch_subtree)
        {
            return GetChangeNotification(completion_filter, watch_subtree, true).Result;
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <param name="token">Cancellation token.</param>
        /// <returns>The list of changes.</returns>
        public async Task<NtResult<IEnumerable<DirectoryChangeNotification>>> GetChangeNotificationAsync(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree, CancellationToken token, bool throw_on_error)
        {
            using (var buffer = new SafeHGlobalBuffer(ChangeNotificationBufferSize))
            {
                var status = await RunFileCallAsync(result => NtSystemCalls.NtNotifyChangeDirectoryFile(
                        Handle, result.EventHandle, IntPtr.Zero, IntPtr.Zero, result.IoStatusBuffer,
                        buffer, buffer.Length, completion_filter, watch_subtree), token, throw_on_error);
                return status.Map(r => ReadNotifications(buffer, r));
            }
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of changes.</returns>
        public Task<NtResult<IEnumerable<DirectoryChangeNotification>>> GetChangeNotificationAsync(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree, bool throw_on_error)
        {
            return GetChangeNotificationAsync(completion_filter, watch_subtree, CancellationToken.None, throw_on_error);
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="token">Cancellation token.</param>
        /// <returns>The list of changes.</returns>
        public async Task<IEnumerable<DirectoryChangeNotification>> GetChangeNotificationAsync(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree, CancellationToken token)
        {
            var result = await GetChangeNotificationAsync(completion_filter, watch_subtree, token, true);
            return result.Result;
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <returns>The list of changes.</returns>
        public Task<IEnumerable<DirectoryChangeNotification>> GetChangeNotificationAsync(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree)
        {
            return GetChangeNotificationAsync(completion_filter, watch_subtree, CancellationToken.None);
        }


        /// <summary>
        /// Get extended change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="timeout">Timeout to wait.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of changes.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS3)]
        public NtResult<IEnumerable<DirectoryChangeNotificationExtended>> GetChangeNotificationEx(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree, NtWaitTimeout timeout, bool throw_on_error)
        {
            using (var buffer = new SafeHGlobalBuffer(ChangeNotificationBufferSize))
            {
                return RunFileCallSync(r => NtSystemCalls.NtNotifyChangeDirectoryFileEx(
                        Handle, r.EventHandle, IntPtr.Zero, IntPtr.Zero, r.IoStatusBuffer,
                        buffer, buffer.Length, completion_filter, watch_subtree,
                        DirectoryNotifyInformationClass.DirectoryNotifyExtendedInformation), timeout, throw_on_error)
                    .Map(s => s.Status == NtStatus.STATUS_SUCCESS ? ReadExtendedNotifications(buffer, s) : new DirectoryChangeNotificationExtended[0]);
            }
        }

        /// <summary>
        /// Get extended change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of changes.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS3)]
        public NtResult<IEnumerable<DirectoryChangeNotificationExtended>> GetChangeNotificationEx(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree, bool throw_on_error)
        {
            return GetChangeNotificationEx(completion_filter, watch_subtree, NtWaitTimeout.Infinite, throw_on_error);
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="timeout">Timeout to wait.</param>
        /// <returns>The list of changes.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS3)]
        public IEnumerable<DirectoryChangeNotificationExtended> GetChangeNotificationEx(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree, NtWaitTimeout timeout)
        {
            return GetChangeNotificationEx(completion_filter, watch_subtree, timeout, true).Result;
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <returns>The list of changes.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS3)]
        public IEnumerable<DirectoryChangeNotificationExtended> GetChangeNotificationEx(DirectoryChangeNotifyFilter completion_filter, bool watch_subtree)
        {
            return GetChangeNotificationEx(completion_filter, watch_subtree, true).Result;
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <param name="token">Cancellation token.</param>
        /// <returns>The list of changes.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS3)]
        public async Task<NtResult<IEnumerable<DirectoryChangeNotificationExtended>>> GetChangeNotificationExAsync(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree, CancellationToken token, bool throw_on_error)
        {
            using (var buffer = new SafeHGlobalBuffer(ChangeNotificationBufferSize))
            {
                var status = await RunFileCallAsync(result => NtSystemCalls.NtNotifyChangeDirectoryFileEx(
                        Handle, result.EventHandle, IntPtr.Zero, IntPtr.Zero, result.IoStatusBuffer,
                        buffer, buffer.Length, completion_filter, watch_subtree, 
                        DirectoryNotifyInformationClass.DirectoryNotifyExtendedInformation), token, throw_on_error);
                return status.Map(r => ReadExtendedNotifications(buffer, r));
            }
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of changes.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS3)]
        public Task<NtResult<IEnumerable<DirectoryChangeNotificationExtended>>> GetChangeNotificationExAsync(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree, bool throw_on_error)
        {
            return GetChangeNotificationExAsync(completion_filter, watch_subtree, CancellationToken.None, throw_on_error);
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <param name="token">Cancellation token.</param>
        /// <returns>The list of changes.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS3)]
        public async Task<IEnumerable<DirectoryChangeNotificationExtended>> GetChangeNotificationExAsync(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree, CancellationToken token)
        {
            var result = await GetChangeNotificationExAsync(completion_filter, watch_subtree, token, true);
            return result.Result;
        }

        /// <summary>
        /// Get change notifications.
        /// </summary>
        /// <param name="completion_filter">The filter of events to watch for.</param>
        /// <param name="watch_subtree">True to watch all sub directories.</param>
        /// <returns>The list of changes.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS3)]
        public Task<IEnumerable<DirectoryChangeNotificationExtended>> GetChangeNotificationExAsync(
            DirectoryChangeNotifyFilter completion_filter, bool watch_subtree)
        {
            return GetChangeNotificationExAsync(completion_filter, watch_subtree, CancellationToken.None);
        }

        /// <summary>
        /// Get the file attributes.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The file attributes.</returns>
        public NtResult<FileAttributes> GetFileAttributes(bool throw_on_error)
        {
            return QueryBasicInformation(throw_on_error).Map(b => b.FileAttributes);
        }

        /// <summary>
        /// Set the file attributes.
        /// </summary>
        /// <param name="file_attributes">The file attributes to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetFileAttributes(FileAttributes file_attributes, bool throw_on_error)
        {
            return SetBasicInformation(new FileBasicInformation() { FileAttributes = file_attributes }, throw_on_error);
        }

        /// <summary>
        /// Get the creation time.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The creation time.</returns>
        public NtResult<DateTime> GetCreationTime(bool throw_on_error)
        {
            return QueryBasicInformation(throw_on_error).Map(b => b.CreationTime.ToDateTime());
        }

        /// <summary>
        /// Get the last write time.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The last write time.</returns>
        public NtResult<DateTime> GetLastWriteTime(bool throw_on_error)
        {
            return QueryBasicInformation(throw_on_error).Map(b => b.LastWriteTime.ToDateTime());
        }

        /// <summary>
        /// Get the change time time.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The change time.</returns>
        public NtResult<DateTime> GetChangeTime(bool throw_on_error)
        {
            return QueryBasicInformation(throw_on_error).Map(b => b.ChangeTime.ToDateTime());
        }

        /// <summary>
        /// Get the last access time.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The last access time time.</returns>
        public NtResult<DateTime> GetLastAccessTime(bool throw_on_error)
        {
            return QueryBasicInformation(throw_on_error).Map(b => b.LastAccessTime.ToDateTime());
        }

        /// <summary>
        /// Set the file's creation time.
        /// </summary>
        /// <param name="time">The time to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetCreationTime(DateTime time, bool throw_on_error)
        {
            return SetBasicInformation(new FileBasicInformation() 
                { CreationTime = time.ToLargeIntegerStruct() }, throw_on_error);
        }

        /// <summary>
        /// Set the file's last access time.
        /// </summary>
        /// <param name="time">The time to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetLastAccessTime(DateTime time, bool throw_on_error)
        {
            return SetBasicInformation(new FileBasicInformation()
            { LastAccessTime = time.ToLargeIntegerStruct() }, throw_on_error);
        }

        /// <summary>
        /// Set the file's last write time.
        /// </summary>
        /// <param name="time">The time to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetLastWriteTime(DateTime time, bool throw_on_error)
        {
            return SetBasicInformation(new FileBasicInformation()
                { LastWriteTime = time.ToLargeIntegerStruct() }, throw_on_error);
        }

        /// <summary>
        /// Set the file's change time.
        /// </summary>
        /// <param name="time">The time to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetChangeTime(DateTime time, bool throw_on_error)
        {
            return SetBasicInformation(new FileBasicInformation()
                { ChangeTime = time.ToLargeIntegerStruct() }, throw_on_error);
        }

        /// <summary>
        /// Set the file position.
        /// </summary>
        /// <param name="position">The file position to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetFilePosition(long position, bool throw_on_error)
        {
            var position_struct = new FilePositionInformation();
            position_struct.CurrentByteOffset.QuadPart = position;
            return Set(FileInformationClass.FilePositionInformation, position_struct, throw_on_error);
        }

        /// <summary>
        /// Get file information.
        /// </summary>
        /// <param name="throw_on_error"></param>
        /// <returns></returns>
        public NtResult<FileInformation> GetFileInformation(bool throw_on_error)
        {
            return Query<FileNetworkOpenInformation>(FileInformationClass.FileNetworkOpenInformation, 
                default, throw_on_error).Map(n => new FileInformation(n));
        }

        /// <summary>
        /// Query all reparse points from a volume.
        /// </summary>
        /// <returns>The list of reparse points.</returns>
        /// <remarks>You'll need to open the reparse database, which is typically \$Extend\$Reparse:$R:$INDEX_ALLOCATION on the volume.</remarks>
        public IEnumerable<NtFileReparsePoint> QueryReparsePoints()
        {
            return QueryFixedDirectoryEntries<FileReparsePointInformation>(FileInformationClass.FileReparsePointInformation).Select(i => new NtFileReparsePoint(this, i)).ToArray();
        }

        /// <summary>
        /// Query all object ids from a volume.
        /// </summary>
        /// <returns>The list of object ids.</returns>
        /// <remarks>You need to open the object ID database, which is typically \$Extend\$ObjId:$O:$INDEX_ALLOCATION on the volume.</remarks>
        public IEnumerable<NtFileObjectId> QueryObjectIds()
        {
            return QueryFixedDirectoryEntries<FileObjectIdInformation>(FileInformationClass.FileObjectIdInformation).Select(i => new NtFileObjectId(this, i)).ToArray();
        }

        /// <summary>
        /// Get the Object ID buffer for a file.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The object ID buffer.</returns>
        public NtResult<FileObjectIdBuffer> GetObjectId(bool throw_on_error)
        {
            using (var buffer = new SafeStructureInOutBuffer<FileObjectIdBuffer>())
            {
                return FsControl(NtWellKnownIoControlCodes.FSCTL_GET_OBJECT_ID,
                    null, buffer, throw_on_error)
                    .Map(i => i == buffer.Length ? buffer.Result : throw new ArgumentException("Invalid length returned."));
            }
        }

        /// <summary>
        /// Get the Object ID create for a file.
        /// </summary>
        /// <returns>The object ID buffer.</returns>
        public FileObjectIdBuffer GetObjectId()
        {
            return GetObjectId(true).Result;
        }

        /// <summary>
        /// Get the Object ID buffer for a file.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The object ID buffer.</returns>
        public NtResult<FileObjectIdBuffer> CreateOrGetObjectId(bool throw_on_error)
        {
            using (var buffer = new SafeStructureInOutBuffer<FileObjectIdBuffer>())
            {
                return FsControl(NtWellKnownIoControlCodes.FSCTL_CREATE_OR_GET_OBJECT_ID,
                    null, buffer, throw_on_error)
                    .Map(i => i == buffer.Length ? buffer.Result : throw new ArgumentException("Invalid length returned."));
            }
        }

        /// <summary>
        /// Get or create the Object ID for a file.
        /// </summary>
        /// <returns>The object ID buffer.</returns>
        public FileObjectIdBuffer CreateOrGetObjectId()
        {
            return CreateOrGetObjectId(true).Result;
        }

        /// <summary>
        /// Set Object ID and extended information.
        /// </summary>
        /// <param name="object_id">The Object ID buffer.</param>
        /// <param name="extended_only">Only set the extended information.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetObjectId(FileObjectIdBuffer object_id, bool extended_only, bool throw_on_error)
        {
            if (object_id.ExtendedInfo?.Length != 48)
            {
                throw new ArgumentException("Extended info needs to be 48 bytes in length.");
            }

            using (var buffer = object_id.ToBuffer())
            {
                return FsControl(extended_only ? NtWellKnownIoControlCodes.FSCTL_SET_OBJECT_ID_EXTENDED : NtWellKnownIoControlCodes.FSCTL_SET_OBJECT_ID, 
                    buffer, null, throw_on_error).Status;
            }
        }

        /// <summary>
        /// Set Object ID and extended information.
        /// </summary>
        /// <param name="object_id">The Object ID buffer.</param>
        /// <param name="extended_only">Only set the extended information.</param>
        /// <returns>The NT status code.</returns>
        public void SetObjectId(FileObjectIdBuffer object_id, bool extended_only)
        {
            SetObjectId(object_id, extended_only, true);
        }

        /// <summary>
        /// Set Object ID and extended information.
        /// </summary>
        /// <param name="object_id">The Object ID GUID.</param>
        /// <param name="extended_info">Extended info buffer, needs to be 48 bytes in size.</param>
        /// <returns>The NT status code.</returns>
        public void SetObjectId(Guid object_id, byte[] extended_info)
        {
            SetObjectId(new FileObjectIdBuffer() { ObjectId = object_id, ExtendedInfo = extended_info }, false);
        }

        /// <summary>
        /// Set only Object ID extended information.
        /// </summary>>
        /// <param name="extended_info">Extended info buffer, needs to be 48 bytes in size.</param>
        /// <returns>The NT status code.</returns>
        public void SetObjectId(byte[] extended_info)
        {
            SetObjectId(new FileObjectIdBuffer() { ExtendedInfo = extended_info }, true);
        }

        /// <summary>
        /// Delete the Object ID for a file.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus DeleteObjectId(bool throw_on_error)
        {
            return FsControl(NtWellKnownIoControlCodes.FSCTL_DELETE_OBJECT_ID, null, null, throw_on_error).Status;
        }

        /// <summary>
        /// Delete the Object ID for a file.
        /// </summary>
        public void DeleteObjectId()
        {
            DeleteObjectId(true);
        }

        /// <summary>
        /// Make the file sparse.
        /// </summary>
        /// <param name="sparse">True to make the file sparse.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetSparse(bool sparse, bool throw_on_error)
        {
            using (var buffer = new FileSetSparseBuffer() { SetSparse = sparse }.ToBuffer())
            {
                return FsControl(NtWellKnownIoControlCodes.FSCTL_SET_SPARSE, buffer, null, throw_on_error).Status;
            }
        }

        /// <summary>
        /// Query if the driver is in the device stack for the device.
        /// </summary>
        /// <param name="driver_path">The driver path. Can be a plain name of full object manager path, e.g. \Device\Blah.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>True indicating driver in path.</returns>
        public NtResult<bool> DriverInPath(string driver_path, bool throw_on_error)
        {
            if (!driver_path.StartsWith(@"\"))
            {
                var res = DriverInPath($@"\Driver\{driver_path}", false);
                if (res.IsSuccess)
                    return res;
                return DriverInPath($@"\FileSystem\{driver_path}", throw_on_error);
            }

            byte[] path = Encoding.Unicode.GetBytes(driver_path);
            FileFsDriverPathInformation info = new FileFsDriverPathInformation() { DriverNameLength = path.Length };
            using (var buffer = info.ToBuffer(path.Length, true))
            {
                buffer.Data.WriteBytes(path);
                return QueryVolume(FsInformationClass.FileFsDriverPathInformation, 
                    buffer, false).CreateResult(throw_on_error, () => buffer.Result.DriverInPath);
            }
        }

        /// <summary>
        /// Query if the driver is in the device stack for the device.
        /// </summary>
        /// <param name="driver_path">The driver path.</param>
        /// <returns>True indicating driver in path.</returns>
        public bool DriverInPath(string driver_path)
        {
            return DriverInPath(driver_path, true).Result;
        }

        /// <summary>
        /// Get filesystem and volume information.
        /// </summary>
        public NtResult<FileSystemVolumeInformation> GetVolumeInformation(bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var attr_info = list.AddResource(QueryVolume<FileFsAttributeInformation>(FsInformationClass.FileFsAttributeInformation, throw_on_error));
                if (!attr_info.IsSuccess)
                    return attr_info.Cast<FileSystemVolumeInformation>();

                var vol_info = list.AddResource(QueryVolume<FileFsVolumeInformation>(FsInformationClass.FileFsVolumeInformation, throw_on_error));
                if (!vol_info.IsSuccess)
                    return vol_info.Cast<FileSystemVolumeInformation>();

                var size_info = QueryVolumeSize(throw_on_error);
                if (!size_info.IsSuccess)
                    return size_info.Cast<FileSystemVolumeInformation>();

                return new FileSystemVolumeInformation(attr_info.Result, vol_info.Result, size_info.Result).CreateResult();
            }
        }

        /// <summary>
        /// Query a fixed buffer for a volume.
        /// </summary>
        /// <typeparam name="T">The type to query.</typeparam>
        /// <param name="info_class">The volume information class.</param>
        /// <returns>The returned type.</returns>
        public T QueryVolumeFixed<T>(FsInformationClass info_class) where T : new()
        {
            return QueryVolumeFixed<T>(info_class, true).Result;
        }

        /// <summary>
        /// Query a fixed buffer for a volume.
        /// </summary>
        /// <typeparam name="T">The type to query.</typeparam>
        /// <param name="info_class">The volume information class.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The returned type.</returns>
        public NtResult<T> QueryVolumeFixed<T>(FsInformationClass info_class, bool throw_on_error) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>())
            {
                IoStatus status = new IoStatus();
                return NtSystemCalls.NtQueryVolumeInformationFile(Handle, status, buffer,
                    buffer.Length, info_class).CreateResult(throw_on_error, () => buffer.Result);
            }
        }

        /// <summary>
        /// Query a buffer for a volume.
        /// </summary>
        /// <typeparam name="T">The type to query.</typeparam>
        /// <param name="info_class">The volume information class.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The returned type.</returns>
        public NtResult<SafeStructureInOutBuffer<T>> QueryVolume<T>(FsInformationClass info_class, bool throw_on_error) where T : new()
        {
            int length = 128;
            while (true)
            {
                using (var buffer = new SafeStructureInOutBuffer<T>(length, true))
                {
                    IoStatus io_status = new IoStatus();
                    NtStatus status = QueryVolume(info_class, buffer, false);
                    if (status.IsSuccess())
                        return status.CreateResult(throw_on_error, () => buffer.Detach());

                    if ((status != NtStatus.STATUS_BUFFER_OVERFLOW) && (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH))
                        return status.CreateResultFromError<SafeStructureInOutBuffer<T>>(throw_on_error);
                }
                length *= 2;
            }
        }

        /// <summary>
        /// Query a buffer for a volume.
        /// </summary>
        /// <param name="info_class">The volume information class.</param>
        /// <param name="init_buffer">Initialization buffer.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The returned type.</returns>
        public NtResult<SafeHGlobalBuffer> QueryVolumeBuffer(FsInformationClass info_class, byte[] init_buffer, bool throw_on_error)
        {
            int length = Math.Max(128, init_buffer?.Length ?? 0);
            while (true)
            {
                using (var buffer = new SafeHGlobalBuffer(length))
                {
                    if (init_buffer != null)
                    {
                        buffer.WriteBytes(0, init_buffer);
                    }
                    IoStatus io_status = new IoStatus();
                    NtStatus status = QueryVolume(info_class, buffer, false);
                    if (status.IsSuccess())
                        return status.CreateResult(throw_on_error, () => buffer.Detach());

                    if ((status != NtStatus.STATUS_BUFFER_OVERFLOW) && (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH))
                        return status.CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
                }
                length *= 2;
            }
        }

        /// <summary>
        /// Query a buffer for a volume.
        /// </summary>
        /// <param name="info_class">The volume information class.</param>
        /// <param name="init_buffer">Initialization buffer.</param>
        /// <returns>The returned type.</returns>
        public SafeHGlobalBuffer QueryVolumeBuffer(FsInformationClass info_class, byte[] init_buffer)
        {
            return QueryVolumeBuffer(info_class, init_buffer, true).Result;
        }

        /// <summary>
        /// Query a buffer for a volume.
        /// </summary>
        /// <typeparam name="T">The type to query.</typeparam>
        /// <param name="info_class">The volume information class.</param>
        /// <returns>The returned type.</returns>
        public SafeStructureInOutBuffer<T> QueryVolume<T>(FsInformationClass info_class) where T : new()
        {
            return QueryVolume<T>(info_class, true).Result;
        }

        /// <summary>
        /// Query a buffer for a volume.
        /// </summary>
        /// <param name="info_class">The volume information class.</param>
        /// <param name="buffer">The buffer for the query. Can be initialized.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus QueryVolume(FsInformationClass info_class, SafeBuffer buffer, bool throw_on_error)
        {
            IoStatus io_status = new IoStatus();
            return NtSystemCalls.NtQueryVolumeInformationFile(Handle, io_status, buffer, 
                buffer.GetLength(), info_class).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Query a buffer for a volume.
        /// </summary>
        /// <param name="info_class">The volume information class.</param>
        /// <param name="buffer">The buffer for the query. Can be initialized.</param>
        public void QueryVolume(FsInformationClass info_class, SafeBuffer buffer)
        {
            QueryVolume(info_class, buffer, true);
        }

        /// <summary>
        /// Set a buffer on a volume.
        /// </summary>
        /// <param name="info_class">The volume information class.</param>
        /// <param name="buffer">The buffer for the set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetVolume(FsInformationClass info_class, SafeBuffer buffer, bool throw_on_error)
        {
            IoStatus io_status = new IoStatus();
            return NtSystemCalls.NtSetVolumeInformationFile(Handle, io_status, buffer,
                buffer.GetLength(), info_class).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Set a buffer on a volume.
        /// </summary>
        /// <param name="info_class">The volume information class.</param>
        /// <param name="buffer">The buffer for the set.</param>
        public void SetVolume(FsInformationClass info_class, SafeBuffer buffer)
        {
            SetVolume(info_class, buffer);
        }

        /// <summary>
        /// Set a fixed value on a volume.
        /// </summary>
        /// <param name="info_class">The volume information class.</param>
        /// <param name="value">The fixed value to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetVolumeFixed<T>(FsInformationClass info_class, T value, bool throw_on_error) where T : new()
        {
            using (var buffer = value.ToBuffer())
            {
                return SetVolume(info_class, buffer, throw_on_error);
            }
        }

        /// <summary>
        /// Set a fixed value on a volume.
        /// </summary>
        /// <param name="info_class">The volume information class.</param>
        /// <param name="value">The fixed value to set.</param>
        public void SetVolumeFixed<T>(FsInformationClass info_class, T value) where T : new()
        {
            SetVolumeFixed(info_class, value, true);
        }

        /// <summary>
        /// Query the quota entries for a volume.
        /// </summary>
        /// <param name="sid_list">Return quote entries for the specified SIDs.</param>
        /// <returns>The list of quota entries.</returns>
        public IEnumerable<FileQuotaEntry> QueryQuota(IEnumerable<Sid> sid_list)
        {
            return QueryQuota(sid_list, null);
        }

        /// <summary>
        /// Query all quota entries for a volume.
        /// </summary>
        /// <returns>The list of quota entries.</returns>
        public IEnumerable<FileQuotaEntry> QueryQuota()
        {
            return QueryQuota(null, null);
        }

        /// <summary>
        /// Set quota entries.
        /// </summary>
        /// <param name="quota_entries">The quota entries to set.</param>
        /// <param name="throw_no_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetQuota(IEnumerable<FileQuotaEntry> quota_entries, bool throw_no_error)
        {
            using (var list = new DisposableList())
            {
                var buffer = ConvertQuotaEntries(quota_entries.ToArray(), list);
                IoStatus io_status = new IoStatus();
                return NtSystemCalls.NtSetQuotaInformationFile(Handle, io_status, buffer, buffer.Length).ToNtException(throw_no_error);
            }
        }

        /// <summary>
        /// Set quota entries.
        /// </summary>
        /// <param name="quota_entries">The quota entries to set.</param>
        public void SetQuota(IEnumerable<FileQuotaEntry> quota_entries)
        {
            SetQuota(quota_entries, true);
        }

        /// <summary>
        /// Set quota entry.
        /// </summary>
        /// <param name="quota_entry">The quota entry to set.</param>
        public void SetQuota(FileQuotaEntry quota_entry)
        {
            SetQuota(new FileQuotaEntry[] { quota_entry });
        }

        /// <summary>
        /// Set quota entry.
        /// </summary>
        /// <param name="sid">The SID for the quota.</param>
        /// <param name="limit">The quota limit to set.</param>
        /// <param name="threshold">The quota threshold to set.</param>
        public void SetQuota(Sid sid, long threshold, long limit)
        {
            SetQuota(new FileQuotaEntry(sid, threshold, limit));
        }

        /// <summary>
        /// Get the file's full path.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The file name.</returns>
        public NtResult<string> GetFileName(bool throw_on_error)
        {
            return TryGetName(FileInformationClass.FileNameInformation, throw_on_error);
        }

        /// <summary>
        /// Get the file's normalized path.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The file name.</returns>
        public NtResult<string> GetNormalizedFileName(bool throw_on_error)
        {
            return TryGetName(FileInformationClass.FileNormalizedNameInformation, throw_on_error);
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

        /// <summary>
        /// Query the information class as an object.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The information class as an object.</returns>
        public override NtResult<object> QueryObject(FileInformationClass info_class, bool throw_on_error)
        {
            switch (info_class)
            {
                case FileInformationClass.FileBasicInformation:
                    return Query<FileBasicInformation>(info_class, default, throw_on_error);
                case FileInformationClass.FileEndOfFileInformation:
                    return Query<FileEndOfFileInformation>(info_class, default, throw_on_error);
                case FileInformationClass.FileStandardInformation:
                    return Query<FileStandardInformation>(info_class, default, throw_on_error);
                case FileInformationClass.FileNetworkOpenInformation:
                    return Query<FileNetworkOpenInformation>(info_class, default, throw_on_error);
                case FileInformationClass.FileInternalInformation:
                    return Query<FileInternalInformation>(info_class, default, throw_on_error);
                case FileInformationClass.FileRemoteProtocolInformation:
                    return Query<FileRemoteProtocolInformation>(info_class, default, throw_on_error);
            }
            return base.QueryObject(info_class, throw_on_error);
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Get object ID for current file
        /// </summary>
        /// <returns>The object ID as a string</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        [Obsolete("Use FileIdValue instead.")]
        public string FileId => NtFileUtils.FileIdToString(FileIdValue);

        /// <summary>
        /// Get object ID for current file as a number.
        /// </summary>
        /// <returns>The object ID as a number.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public long FileIdValue => Query<FileInternalInformation>(FileInformationClass.FileInternalInformation).IndexNumber.QuadPart;

        /// <summary>
        /// Get or set the attributes of a file.
        /// </summary>
        /// <returns>The file attributes</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public FileAttributes FileAttributes
        {
            get => GetFileAttributes(true).Result;
            set => SetFileAttributes(value, true);
        }

        /// <summary>
        /// Get or set the creation time.
        /// </summary>
        public DateTime FileCreationTime
        {
            get => GetCreationTime(true).Result;
            set => SetCreationTime(value, true);
        }

        /// <summary>
        /// Get or set the last access time.
        /// </summary>
        public DateTime LastAccessTime
        {
            get => GetLastAccessTime(true).Result;
            set => SetLastAccessTime(value, true);
        }

        /// <summary>
        /// Get or set the last write time.
        /// </summary>
        public DateTime LastWriteTime
        {
            get => GetLastWriteTime(true).Result;
            set => SetLastWriteTime(value, true);
        }

        /// <summary>
        /// Get or set the change time.
        /// </summary>
        public DateTime ChangeTime
        {
            get => GetChangeTime(true).Result;
            set => SetChangeTime(value, true);
        }

        /// <summary>
        /// Get file information, which is times, attributes and sizes.
        /// </summary>
        public FileInformation FileInformation => GetFileInformation(true).Result;

        /// <summary>
        /// Get or set the file as sparse.
        /// </summary>
        public bool Sparse
        {
            get => FileAttributes.HasFlagSet(FileAttributes.SparseFile);
            set => SetSparse(value, true);
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
                    var info = Query<FileStandardInformation>(FileInformationClass.FileStandardInformation, default, false).GetResultOrDefault();
                    _is_directory = info.Directory;
                }
                return _is_directory.Value;
            }
        }

        /// <summary>
        /// Get whether this file repsents a reparse point.
        /// </summary>
        public bool IsReparsePoint => GetFileAttributes(false).GetResultOrDefault(FileAttributes.None).HasFlagSet(FileAttributes.ReparsePoint);

        /// <summary>
        /// The result of opening the file, whether it was created, overwritten etc.
        /// </summary>
        public FileOpenResult OpenResult { get; }

        /// <summary>
        /// Get or set the current file position.
        /// </summary>
        public long Position
        {
            get => Query<FilePositionInformation>(FileInformationClass.FilePositionInformation).CurrentByteOffset.QuadPart;
            set => SetFilePosition(value, true);
        }

        /// <summary>
        /// Get or sets the file's length
        /// </summary>
        public long Length
        {
            get => Query<FileStandardInformation>(FileInformationClass.FileStandardInformation).EndOfFile.QuadPart;
            set => SetEndOfFile(value);
        }

        /// <summary>
        /// Get the file's allocation size.
        /// </summary>
        public long AllocationSize => Query<FileStandardInformation>(FileInformationClass.FileStandardInformation).AllocationSize.QuadPart;

        /// <summary>
        /// Get the number of links.
        /// </summary>
        public int NumberOfLinks => Query<FileStandardInformation>(FileInformationClass.FileStandardInformation).NumberOfLinks;

        /// <summary>
        /// Get whether delete is pending.
        /// </summary>
        public bool DeletePending => Query<FileStandardInformation>(FileInformationClass.FileStandardInformation).DeletePending;

        /// <summary>
        /// Get the Win32 path name for the file.
        /// </summary>
        /// <returns>The path, string.Empty on error.</returns>
        public string Win32PathName => GetWin32PathName(Win32PathNameFlags.None, false).GetResultOrDefault(string.Empty);

        /// <summary>
        /// Get the low-level device type of the file.
        /// </summary>
        /// <returns>The file device type.</returns>
        public FileDeviceType DeviceType => QueryVolumeFixed<FileFsDeviceInformation>(
            FsInformationClass.FileFsDeviceInformation, false).GetResultOrDefault()?.DeviceType ?? FileDeviceType.UNKNOWN;

        /// <summary>
        /// Get the low-level device characteristics of the file.
        /// </summary>
        /// <returns>The file device characteristics.</returns>
        public FileDeviceCharacteristics Characteristics => QueryVolumeFixed<FileFsDeviceInformation>(
            FsInformationClass.FileFsDeviceInformation, false).GetResultOrDefault()?.Characteristics ?? FileDeviceCharacteristics.None;

        /// <summary>
        /// Get filesystem and volume information.
        /// </summary>
        public FileSystemVolumeInformation VolumeInformation => GetVolumeInformation(true).Result;

        /// <summary>
        /// Get or set the file's compression format.
        /// </summary>
        public CompressionFormat CompressionFormat
        {
            get
            {
                using (var buffer = new SafeStructureInOutBuffer<short>())
                {
                    FsControl(NtWellKnownIoControlCodes.FSCTL_GET_COMPRESSION, SafeHGlobalBuffer.Null, buffer);
                    return (CompressionFormat)buffer.Result;
                }
            }
            set
            {
                using (var buffer = ((short)value).ToBuffer())
                {
                    FsControl(NtWellKnownIoControlCodes.FSCTL_SET_COMPRESSION, buffer, SafeHGlobalBuffer.Null);
                }
            }
        }

        /// <summary>
        /// Gets whether the file is on a remote file system.
        /// </summary>
        public bool IsRemote => Query<bool>(FileInformationClass.FileIsRemoteDeviceInformation);

        /// <summary>
        /// Get or set whether this file/directory is case sensitive.
        /// </summary>
        public bool CaseSensitive
        {
            get
            {
                return CaseSensitiveFlags.HasFlagSet(FileCaseSensitiveFlags.CaseSensitiveDir);
            }

            set
            {
                var flags = CaseSensitiveFlags;
                if (value)
                {
                    flags |= FileCaseSensitiveFlags.CaseSensitiveDir;
                }
                else
                {
                    flags &= ~FileCaseSensitiveFlags.CaseSensitiveDir;
                }

                var info = new FileCaseSensitiveInformation()
                {
                    Flags = flags
                };

                Set(FileInformationClass.FileCaseSensitiveInformation, info);
            }
        }

        /// <summary>
        /// Get or set whether this file/directory is case sensitive.
        /// </summary>
        public FileCaseSensitiveFlags CaseSensitiveFlags
        {
            get
            {
                var result = Query(FileInformationClass.FileCaseSensitiveInformation, new FileCaseSensitiveInformation(), false);
                if (!result.IsSuccess)
                {
                    return FileCaseSensitiveFlags.None;
                }

                return result.Result.Flags;
            }

            set
            {
                var info = new FileCaseSensitiveInformation()
                {
                    Flags = value
                };

                Set(FileInformationClass.FileCaseSensitiveInformation, info);
            }
        }

        /// <summary>
        /// Get the file mode.
        /// </summary>
        public FileOpenOptions Mode => QueryEnum<FileOpenOptions>(FileInformationClass.FileModeInformation);

        /// <summary>
        /// Get file access information.
        /// </summary>
        public AccessMask Access => Query<AccessMask>(FileInformationClass.FileAccessInformation);

        /// <summary>
        /// Get the filename with the volume path.
        /// </summary>
        public string FileName => TryGetName(FileInformationClass.FileNameInformation, true).Result;

        /// <summary>
        /// Get the normalized filename with the volume path.
        /// </summary>
        public string NormalizedFileName => TryGetName(FileInformationClass.FileNormalizedNameInformation, true).Result;

        /// <summary>
        /// Get the associated short filename
        /// </summary>
        [Obsolete("Use ShortName")]
        public string FileShortName
        {
            get => ShortName;
            set => ShortName = value;
        }

        /// <summary>
        /// Get the associated short filename
        /// </summary>
        public string ShortName
        {
            get => TryGetName(FileInformationClass.FileAlternateNameInformation, true).Result;
            set => SetName(FileInformationClass.FileShortNameInformation, value);
        }

        /// <summary>
        /// Get the normalized name.
        /// </summary>
        public string NormalizedName => Path.GetFileName(NormalizedFileName);

        /// <summary>
        /// Get or set the storage reserve ID.
        /// </summary>
        public StorageReserveId StorageReserveId
        {
            get => Query<FileStorageReserveIdInformation>(FileInformationClass.FileStorageReserveIdInformation).StorageReserveId;
            set => Set(FileInformationClass.FileStorageReserveIdInformation, new FileStorageReserveIdInformation() { StorageReserveId = value });
        }

        /// <summary>
        /// Returns whether this object is a container.
        /// </summary>
        public override bool IsContainer => IsDirectory;

        /// <summary>
        /// Get or set the read only status of the file.
        /// </summary>
        public bool ReadOnly
        {
            get => FileAttributes.HasFlagSet(FileAttributes.ReadOnly);
            set
            {
                var current_attributes = FileAttributes;
                if (value)
                {
                    current_attributes |= FileAttributes.ReadOnly;
                }
                else
                {
                    current_attributes &= ~FileAttributes.ReadOnly;
                    if (current_attributes == 0)
                    {
                        current_attributes = FileAttributes.Normal;
                    }
                }
                FileAttributes = current_attributes;
            }
        }

        /// <summary>
        /// Is the file compressed.
        /// </summary>
        public bool Compressed => FileAttributes.HasFlagSet(FileAttributes.Compressed);

        /// <summary>
        /// Get remote protocol information.
        /// </summary>
        public FileRemoteProtocol RemoteProtocol
        {
            get
            {
                FileRemoteProtocolInformation info = new FileRemoteProtocolInformation();
                info.StructureSize = (ushort)Marshal.SizeOf(info);
                if (NtObjectUtils.IsWindows7OrLess)
                    info.StructureVersion = 1;
                else
                    info.StructureVersion = 2;
                return new FileRemoteProtocol(Query(FileInformationClass.FileRemoteProtocolInformation, info));
            }
        }

        /// <summary>
        /// Get the granted access as directory rights.
        /// </summary>
        public FileDirectoryAccessRights DirectoryGrantedAccess => GrantedAccessMask.ToSpecificAccess<FileDirectoryAccessRights>();

        /// <summary>
        /// Get the file system control flags.
        /// </summary>
        public FileSystemControlFlags ControlFlags => QueryVolumeFixed<FileFsControlInformation>(FsInformationClass.FileFsControlInformation).FileSystemControlFlags;

        /// <summary>
        /// Get persist volume flags.
        /// </summary>
        public FileFsPersistentVolumeInformationFlags PersistentVolumeFlags
        {
            get
            {
                FileFsPersistentVolumeInformation vol_info = new FileFsPersistentVolumeInformation()
                {
                    Version = 1,
                    FlagMask = (FileFsPersistentVolumeInformationFlags)uint.MaxValue
                };

                using (var in_buffer = vol_info.ToBuffer())
                {
                    using (var out_buffer = new SafeStructureInOutBuffer<FileFsPersistentVolumeInformation>())
                    {
                        int size = FsControl(NtWellKnownIoControlCodes.FSCTL_QUERY_PERSISTENT_VOLUME_STATE, in_buffer, out_buffer);
                        if (size != out_buffer.Length)
                            throw new NtException(NtStatus.STATUS_BUFFER_TOO_SMALL);
                        return out_buffer.Result.VolumeFlags;
                    }
                }
            }
        }

        #endregion
    }
}
