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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to access some NT system information
    /// </summary>
    public static class NtSystemInfo
    {
        #region Private Members

        // A dummy system info object to repurpose the query/set methods.
        private class NtSystemInfoObject : NtObjectWithDuplicateAndInfo<NtGeneric, GenericAccessRights, SystemInformationClass, SystemInformationClass>
        {
            public NtSystemInfoObject() : base(SafeKernelObjectHandle.Null)
            {
            }

            protected override int GetMaximumBruteForceLength(SystemInformationClass info_class)
            {
                return 16 * 1024 * 1024;
            }

            protected override bool GetTrustReturnLength(SystemInformationClass info_class)
            {
                return false;
            }

            public override NtStatus QueryInformation(SystemInformationClass info_class, SafeBuffer buffer, out int return_length)
            {
                return NtSystemCalls.NtQuerySystemInformation(info_class, buffer, buffer.GetLength(), out return_length);
            }

            public override NtStatus SetInformation(SystemInformationClass info_class, SafeBuffer buffer)
            {
                return NtSystemCalls.NtSetSystemInformation(info_class, buffer, buffer.GetLength());
            }
        }

        private static readonly Dictionary<SystemInformationClass, object> _cached_info = new Dictionary<SystemInformationClass, object>();
        private static readonly NtSystemInfoObject _system_info_object = new NtSystemInfoObject();

        private static T QueryCached<T>(SystemInformationClass info_class) where T : new()
        {
            if (!_cached_info.ContainsKey(info_class))
            {
                var value = Query(info_class, default(T), false);
                if (value.IsSuccess)
                {
                    _cached_info[info_class] = value.Result;
                }
                else
                {
                    _cached_info[info_class] = default(T);
                }
            }
            return (T)_cached_info[info_class];
        }

        private static SystemBasicInformation GetBasicInfo()
        {
            return QueryCached<SystemBasicInformation>(SystemInformationClass.SystemBasicInformation);
        }

        private static SystemKernelDebuggerInformation GetKernelDebuggerInformation()
        {
            return Query<SystemKernelDebuggerInformation>(SystemInformationClass.SystemKernelDebuggerInformation);
        }

        private static SafeHGlobalBuffer EnumEnvironmentValues(SystemEnvironmentValueInformationClass info_class)
        {
            int ret_length = 0;
            NtStatus status = NtSystemCalls.NtEnumerateSystemEnvironmentValuesEx(info_class, SafeHGlobalBuffer.Null, ref ret_length);
            if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
            {
                throw new NtException(status);
            }
            var buffer = new SafeHGlobalBuffer(ret_length);
            try
            {
                ret_length = buffer.Length;
                NtSystemCalls.NtEnumerateSystemEnvironmentValuesEx(info_class,
                    buffer, ref ret_length).ToNtException();
                return buffer;
            }
            catch
            {
                buffer.Dispose();
                throw;
            }
        }

        private static IEnumerable<NtThreadInformation> ReadThreadInformation(SafeStructureInOutBuffer<SystemProcessInformation> process_buffer, string image_name, int thread_count)
        {
            SystemThreadInformation[] thread_info = new SystemThreadInformation[thread_count];
            process_buffer.Data.ReadArray(0, thread_info, 0, thread_info.Length);

            return thread_info.Select(t => new NtThreadInformation(image_name, t));
        }

        private static IEnumerable<NtThreadInformation> ReadExtendedThreadInformation(SafeStructureInOutBuffer<SystemProcessInformation> process_buffer, string image_name, int thread_count)
        {
            SystemExtendedThreadInformation[] thread_info = new SystemExtendedThreadInformation[thread_count];
            process_buffer.Data.ReadArray(0, thread_info, 0, thread_info.Length);

            return thread_info.Select(t => new NtThreadInformationExtended(image_name, t));
        }

        private static NtResult<List<NtProcessInformation>> QueryProcessInformation(SystemInformationClass info_class, bool throw_on_error)
        {
            List<NtProcessInformation> ret = new List<NtProcessInformation>();
            using (var process_info = QueryBuffer<SystemProcessInformation>(info_class, default, throw_on_error))
            {
                if (!process_info.IsSuccess)
                {
                    return process_info.Cast<List<NtProcessInformation>>();
                }

                int offset = 0;
                while (true)
                {
                    var process_buffer = process_info.Result.GetStructAtOffset<SystemProcessInformation>(offset);
                    var process_entry = process_buffer.Result;
                    string image_name = process_entry.UniqueProcessId == IntPtr.Zero ? "Idle"
                                : process_entry.ImageName.ToString();

                    IEnumerable<NtThreadInformation> thread_info;
                    if (info_class == SystemInformationClass.SystemProcessInformation)
                    {
                        thread_info = ReadThreadInformation(process_buffer, image_name, process_entry.NumberOfThreads);
                    }
                    else
                    {
                        thread_info = ReadExtendedThreadInformation(process_buffer, image_name, process_entry.NumberOfThreads);
                    }

                    ret.Add(new NtProcessInformation(process_entry, thread_info, info_class == SystemInformationClass.SystemFullProcessInformation));

                    if (process_entry.NextEntryOffset == 0)
                    {
                        break;
                    }

                    offset += process_entry.NextEntryOffset;
                }
            }

            return ret.CreateResult();
        }

        #endregion

        #region Static Methods

        /// <summary>
        /// Get a list of handles
        /// </summary>
        /// <param name="pid">A process ID to filter on. If -1 will get all handles</param>
        /// <param name="allow_query">True to allow the handles returned to query for certain properties</param>
        /// <returns>The list of handles</returns>
        public static IEnumerable<NtHandle> GetHandles(int pid, bool allow_query)
        {
            using (var buffer = QueryBuffer<SystemHandleInformationEx>(SystemInformationClass.SystemExtendedHandleInformation))
            {
                var handle_info = buffer.Result;
                int handle_count = handle_info.NumberOfHandles.ToInt32();
                SystemHandleTableInfoEntryEx[] handles = new SystemHandleTableInfoEntryEx[handle_count];
                buffer.Data.ReadArray(0, handles, 0, handle_count);
                return handles.Where(h => pid == -1 || h.UniqueProcessId.ToInt32() == pid).Select(h => new NtHandle(h, allow_query));
            }
        }

        /// <summary>
        /// Get a list of all handles
        /// </summary>
        /// <returns>The list of handles</returns>
        public static IEnumerable<NtHandle> GetHandles()
        {
            return GetHandles(-1, true);
        }

        /// <summary>
        /// Get a list of threads for a specific process.
        /// </summary>
        /// <param name="process_id">The process ID to list.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of thread information.</returns>
        public static NtResult<IEnumerable<NtThreadInformation>> GetThreadInformation(int process_id, bool throw_on_error)
        {
            var procs = GetProcessInformation(throw_on_error);
            if (!procs.IsSuccess)
            {
                return procs.Cast<IEnumerable<NtThreadInformation>>();
            }

            foreach (var process in procs.Result)
            {
                if (process.ProcessId == process_id)
                {
                    return process.Threads.CreateResult();
                }
            }

            return new NtThreadInformation[0].CreateResult<IEnumerable<NtThreadInformation>>();
        }

        /// <summary>
        /// Get a list of threads for a specific process.
        /// </summary>
        /// <param name="process_id">The process ID to list.</param>
        /// <returns>The list of thread information.</returns>
        public static IEnumerable<NtThreadInformation> GetThreadInformation(int process_id)
        {
            return GetThreadInformation(process_id, true).Result;
        }

        /// <summary>
        /// Get a list of all threads.
        /// </summary>
        /// <returns>The list of thread information.</returns>
        public static NtResult<IEnumerable<NtThreadInformation>> GetThreadInformation(bool throw_on_error)
        {
            var procs = GetProcessInformation(throw_on_error);
            if (!procs.IsSuccess)
            {
                return new NtThreadInformation[0].CreateResult<IEnumerable<NtThreadInformation>>();
            }
            return procs.Result.SelectMany(p => p.Threads).CreateResult();
        }

        /// <summary>
        /// Get a list of all threads.
        /// </summary>
        /// <returns>The list of thread information.</returns>
        public static IEnumerable<NtThreadInformation> GetThreadInformation()
        {
            return GetThreadInformation(true).Result;
        }

        /// <summary>
        /// Get a list of threads for a specific process.
        /// </summary>
        /// <param name="process_id">The process ID to list.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of thread information.</returns>
        public static NtResult<IEnumerable<NtThreadInformationExtended>> GetThreadInformationExtended(int process_id, bool throw_on_error)
        {
            var procs = GetProcessInformationExtended(throw_on_error);
            if (!procs.IsSuccess)
            {
                return procs.Cast<IEnumerable<NtThreadInformationExtended>>();
            }

            foreach (var process in procs.Result)
            {
                if (process.ProcessId == process_id)
                {
                    return process.Threads.Cast<NtThreadInformationExtended>().CreateResult();
                }
            }

            return new NtThreadInformationExtended[0].CreateResult<IEnumerable<NtThreadInformationExtended>>();
        }

        /// <summary>
        /// Get a list of threads for a specific process.
        /// </summary>
        /// <param name="process_id">The process ID to list.</param>
        /// <returns>The list of thread information.</returns>
        public static IEnumerable<NtThreadInformationExtended> GetThreadInformationExtended(int process_id)
        {
            return GetThreadInformationExtended(process_id, true).Result;
        }

        /// <summary>
        /// Get a list of all threads.
        /// </summary>
        /// <returns>The list of thread information.</returns>
        public static NtResult<IEnumerable<NtThreadInformationExtended>> GetThreadInformationExtended(bool throw_on_error)
        {
            var procs = GetProcessInformationExtended(throw_on_error);
            if (!procs.IsSuccess)
            {
                return new NtThreadInformationExtended[0].CreateResult<IEnumerable<NtThreadInformationExtended>>();
            }
            return procs.Result.SelectMany(p => p.Threads).Cast<NtThreadInformationExtended>().CreateResult();
        }

        /// <summary>
        /// Get a list of all threads.
        /// </summary>
        /// <returns>The list of thread information.</returns>
        public static IEnumerable<NtThreadInformationExtended> GetThreadInformationExtended()
        {
            return GetThreadInformationExtended(true).Result;
        }

        /// <summary>
        /// Get all process information for the system.
        /// </summary>
        /// <returns>The list of process information.</returns>
        public static IEnumerable<NtProcessInformation> GetProcessInformation()
        {
            return GetProcessInformation(true).Result;
        }

        /// <summary>
        /// Get all process information for the system.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of process information.</returns>
        public static NtResult<IEnumerable<NtProcessInformation>> GetProcessInformation(bool throw_on_error)
        {
            return QueryProcessInformation(SystemInformationClass.SystemProcessInformation, throw_on_error).Map<IEnumerable<NtProcessInformation>>(p => p.AsReadOnly());
        }

        /// <summary>
        /// Get all process information for the system.
        /// </summary>
        /// <returns>The list of process information.</returns>
        public static IEnumerable<NtProcessInformation> GetProcessInformationExtended()
        {
            return GetProcessInformationExtended(true).Result;
        }

        /// <summary>
        /// Get all process information for the system.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of process information.</returns>
        public static NtResult<IEnumerable<NtProcessInformation>> GetProcessInformationExtended(bool throw_on_error)
        {
            return QueryProcessInformation(SystemInformationClass.SystemExtendedProcessInformation, throw_on_error).Map<IEnumerable<NtProcessInformation>>(p => p.AsReadOnly());
        }

        /// <summary>
        /// Get all process information for the system.
        /// </summary>
        /// <returns>The list of process information.</returns>
        public static IEnumerable<NtProcessInformation> GetProcessInformationFull()
        {
            return GetProcessInformationFull(true).Result;
        }

        /// <summary>
        /// Get all process information for the system.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of process information.</returns>
        public static NtResult<IEnumerable<NtProcessInformation>> GetProcessInformationFull(bool throw_on_error)
        {
            return QueryProcessInformation(SystemInformationClass.SystemFullProcessInformation, throw_on_error).Map<IEnumerable<NtProcessInformation>>(p => p.AsReadOnly());
        }

        /// <summary>
        /// Get list of page filenames.
        /// </summary>
        /// <returns>The list of page file names.</returns>
        public static IEnumerable<string> GetPageFileNames()
        {
            using (var buffer = QueryBuffer<SystemPageFileInformation>(SystemInformationClass.SystemPageFileInformation))
            {
                int offset = 0;
                while (true)
                {
                    var pagefile_info = buffer.GetStructAtOffset<SystemPageFileInformation>(offset).Result;
                    yield return pagefile_info.PageFileName.ToString();
                    if (pagefile_info.NextEntryOffset == 0)
                    {
                        break;
                    }
                    offset += pagefile_info.NextEntryOffset;
                }
            }
        }

        /// <summary>
        /// Create a kernel dump for current system.
        /// </summary>
        /// <param name="path">The path to the output file.</param>
        /// <param name="flags">Flags</param>
        /// <param name="page_flags">Page flags</param>
        public static void CreateKernelDump(string path, SystemDebugKernelDumpControlFlags flags, SystemDebugKernelDumpPageControlFlags page_flags)
        {
            NtToken.EnableDebugPrivilege();
            using (NtFile file = NtFile.Create(path, FileAccessRights.Synchronize | FileAccessRights.GenericWrite | FileAccessRights.GenericRead,
                    FileShareMode.Read, FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.WriteThrough | FileOpenOptions.NoIntermediateBuffering, FileDisposition.OverwriteIf,
                    null))
            {
                using (var buffer = new SystemDebugKernelDumpConfig()
                {
                    FileHandle = file.Handle.DangerousGetHandle(),
                    Flags = flags,
                    PageFlags = page_flags
                }.ToBuffer())
                {
                    NtSystemCalls.NtSystemDebugControl(SystemDebugCommand.SysDbgGetLiveKernelDump, buffer, buffer.Length,
                        SafeHGlobalBuffer.Null, 0, out int ret_length).ToNtException();
                }
            }
        }

        /// <summary>
        /// Query all system environment value names.
        /// </summary>
        /// <returns>A list of names of environment values</returns>
        public static IEnumerable<string> QuerySystemEnvironmentValueNames()
        {
            using (var buffer = EnumEnvironmentValues(SystemEnvironmentValueInformationClass.NamesOnly))
            {
                int offset = 0;
                int size_struct = Marshal.SizeOf(typeof(SystemEnvironmentValueName));
                while (offset <= buffer.Length - size_struct)
                {
                    var struct_buffer = buffer.GetStructAtOffset<SystemEnvironmentValueName>(offset);
                    SystemEnvironmentValueName name = struct_buffer.Result;
                    yield return struct_buffer.Data.ReadNulTerminatedUnicodeString();
                    if (name.NextEntryOffset == 0)
                    {
                        break;
                    }
                    offset = offset + name.NextEntryOffset;
                }
            }
        }

        /// <summary>
        /// Query all system environment value names and values.
        /// </summary>
        /// <returns>A list of names of environment values</returns>
        public static IEnumerable<SystemEnvironmentValue> QuerySystemEnvironmentValueNamesAndValues()
        {
            using (var buffer = EnumEnvironmentValues(SystemEnvironmentValueInformationClass.NamesAndValues))
            {
                int offset = 0;
                int size_struct = Marshal.SizeOf(typeof(SystemEnvironmentValueNameAndValue));
                while (offset <= buffer.Length - size_struct)
                {
                    var struct_buffer = buffer.GetStructAtOffset<SystemEnvironmentValueNameAndValue>(offset);
                    SystemEnvironmentValueNameAndValue name = struct_buffer.Result;
                    yield return new SystemEnvironmentValue(struct_buffer);
                    if (name.NextEntryOffset == 0)
                    {
                        break;
                    }
                    offset = offset + name.NextEntryOffset;
                }
            }
        }

        /// <summary>
        /// Query a single system environment value.
        /// </summary>
        /// <param name="name">The name of the value.</param>
        /// <param name="vendor_guid">The associated vendor guid</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The system environment value.</returns>
        public static NtResult<SystemEnvironmentValue> QuerySystemEnvironmentValue(string name, Guid vendor_guid, bool throw_on_error)
        {
            UnicodeString name_string = new UnicodeString(name);
            int value_length = 0;
            NtStatus status = NtSystemCalls.NtQuerySystemEnvironmentValueEx(name_string, ref vendor_guid, null, ref value_length, 0);
            if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
            {
                return status.CreateResultFromError<SystemEnvironmentValue>(throw_on_error);
            }

            byte[] value = new byte[value_length];
            OptionalInt32 attributes = new OptionalInt32();
            return NtSystemCalls.NtQuerySystemEnvironmentValueEx(name_string, ref vendor_guid, value, ref value_length, attributes)
                .CreateResult(throw_on_error, () => new SystemEnvironmentValue(name, value, attributes, vendor_guid));
        }

        /// <summary>
        /// Query a single system environment value.
        /// </summary>
        /// <param name="name">The name of the value.</param>
        /// <param name="vendor_guid">The associated vendor guid</param>
        /// <returns>The system environment value.</returns>
        public static SystemEnvironmentValue QuerySystemEnvironmentValue(string name, Guid vendor_guid)
        {
            return QuerySystemEnvironmentValue(name, vendor_guid, true).Result;
        }

        /// <summary>
        /// Set a system environment variable.
        /// </summary>
        /// <param name="name">The name of the variable.</param>
        /// <param name="vendor_guid">The vendor GUID</param>
        /// <param name="value">The value to set</param>
        /// <param name="attributes">Attributes of the value</param>
        public static void SetSystemEnvironmentValue(string name, Guid vendor_guid, byte[] value, int attributes)
        {
            NtSystemCalls.NtSetSystemEnvironmentValueEx(new UnicodeString(name), ref vendor_guid, value, value.Length, attributes).ToNtException();
        }

        /// <summary>
        /// Set a system environment variable.
        /// </summary>
        /// <param name="name">The name of the variable.</param>
        /// <param name="vendor_guid">The vendor GUID</param>
        /// <param name="value">The value to set</param>
        /// <param name="attributes">Attributes of the value</param>
        public static void SetSystemEnvironmentValue(string name, Guid vendor_guid, byte[] value, SystemEnvironmentValueAttribute attributes)
        {
            SetSystemEnvironmentValue(name, vendor_guid, value, (int)attributes);
        }

        /// <summary>
        /// Set a system environment variable.
        /// </summary>
        /// <param name="name">The name of the variable.</param>
        /// <param name="vendor_guid">The vendor GUID</param>
        /// <param name="value">The value to set</param>
        /// <param name="attributes">Attributes of the value</param>
        public static void SetSystemEnvironmentValue(string name, Guid vendor_guid, string value, int attributes)
        {
            SetSystemEnvironmentValue(name, vendor_guid, Encoding.Unicode.GetBytes(value), attributes);
        }

        /// <summary>
        /// Set a system environment variable.
        /// </summary>
        /// <param name="name">The name of the variable.</param>
        /// <param name="vendor_guid">The vendor GUID</param>
        /// <param name="value">The value to set</param>
        /// <param name="attributes">Attributes of the value</param>
        public static void SetSystemEnvironmentValue(string name, Guid vendor_guid, string value, SystemEnvironmentValueAttribute attributes)
        {
            SetSystemEnvironmentValue(name, vendor_guid, value, (int)attributes);
        }

        /// <summary>
        /// Allocate a LUID.
        /// </summary>
        /// <returns>The allocated LUID.</returns>
        public static Luid AllocateLocallyUniqueId()
        {
            NtSystemCalls.NtAllocateLocallyUniqueId(out Luid luid).ToNtException();
            return luid;
        }

        /// <summary>
        /// Get the addresses of a list of objects from the handle table and initialize the Address property.
        /// </summary>
        /// <param name="objects">The list of objects to initialize.</param>
        public static void ResolveObjectAddress(IEnumerable<NtObject> objects)
        {
            var handles = GetHandles(NtProcess.Current.ProcessId, false).ToDictionary(h => h.Handle, h => h.Object);
            foreach (var obj in objects)
            {
                int obj_handle = obj.Handle.DangerousGetHandle().ToInt32();
                if (handles.ContainsKey(obj_handle))
                {
                    obj.Address = handles[obj_handle];
                }
            }
        }

        /// <summary>
        /// Get the address of an object in kernel memory from the handle table and initialize the Address property.
        /// </summary>
        /// <param name="obj">The object.</param>
        public static void ResolveObjectAddress(NtObject obj)
        {
            ResolveObjectAddress(new[] { obj });
        }

        /// <summary>
        /// Get the address of an object in kernel memory from the handle table and initialize the Address property.
        /// </summary>
        /// <param name="obj">The object.</param>
        /// <param name="objs">Any remaining objects.</param>
        public static void ResolveObjectAddress(NtObject obj, params NtObject[] objs)
        {
            List<NtObject> list = new List<NtObject>();
            list.Add(obj);
            list.AddRange(objs);
            ResolveObjectAddress(list);
        }

        /// <summary>
        /// Query whether a file is trusted for dynamic code.
        /// </summary>
        /// <param name="handle">The handle to a file to query.</param>
        /// <param name="image">Pointer to a memory buffer containing the image.</param>
        /// <param name="image_size">The size of the in-memory buffer.</param>
        /// <returns>True if the file is trusted.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS4)]
        public static NtStatus QueryDynamicCodeTrust(SafeKernelObjectHandle handle, IntPtr image, int image_size)
        {
            SystemCodeIntegrityVerificationInformation info = new SystemCodeIntegrityVerificationInformation()
            {
                FileHandle = handle.DangerousGetHandle(),
                Image = image,
                ImageSize = image_size
            };

            return Query(SystemInformationClass.SystemCodeIntegrityVerificationInformation, info, false).Status;
        }

        /// <summary>
        /// Query whether a file is trusted for dynamic code.
        /// </summary>
        /// <param name="image">Pointer to a memory buffer containing the image.</param>
        /// <returns>The status code from the operation. Returns STATUS_SUCCESS is valid.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS4)]
        public static NtStatus QueryDynamicCodeTrust(byte[] image)
        {
            using (var buffer = image.ToBuffer())
            {
                return QueryDynamicCodeTrust(SafeKernelObjectHandle.Null,
                    buffer.DangerousGetHandle(), buffer.Length);
            }
        }

        /// <summary>
        /// Query whether a file is trusted for dynamic code.
        /// </summary>
        /// <param name="handle">The handle to a file to query.</param>
        /// <returns>The status code from the operation. Returns STATUS_SUCCESS is valid.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS4)]
        public static NtStatus QueryDynamicCodeTrust(SafeKernelObjectHandle handle)
        {
            return QueryDynamicCodeTrust(handle, IntPtr.Zero, 0);
        }

        /// <summary>
        /// Set a file is trusted for dynamic code.
        /// </summary>
        /// <param name="handle">The handle to a file to set.</param>
        /// <returns>The status code from the operation.</returns>
        [SupportedVersion(SupportedVersion.Windows10_RS4)]
        public static NtStatus SetDynamicCodeTrust(SafeKernelObjectHandle handle)
        {
            SystemCodeIntegrityVerificationInformation info = new SystemCodeIntegrityVerificationInformation()
            {
                FileHandle = handle.DangerousGetHandle()
            };

            return Set(SystemInformationClass.SystemCodeIntegrityVerificationInformation, info, false);
        }

        /// <summary>
        /// Get list of root silos.
        /// </summary>
        /// <returns>The list of root silos.</returns>
        public static IReadOnlyCollection<int> GetRootSilos()
        {
            using (var buffer = QueryBuffer<SystemRootSiloInformation>(SystemInformationClass.SystemRootSiloInformation))
            {
                var result = buffer.Result;
                int[] silos = new int[result.NumberOfSilos];
                buffer.Data.ReadArray(0, silos, 0, silos.Length);
                return silos.ToList().AsReadOnly();
            }
        }

        /// <summary>
        /// Set the ELAM certificate information.
        /// </summary>
        /// <param name="image_file">The signed file containing an ELAM certificate resource.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetElamCertificate(NtFile image_file)
        {
            SystemElamCertificateInformation info = new SystemElamCertificateInformation()
            { ElamDriverFile = image_file.Handle.DangerousGetHandle() };
            return Set(SystemInformationClass.SystemElamCertificateInformation, info, false);
        }

        /// <summary>
        /// Query code integrity certificate information.
        /// </summary>
        /// <param name="image_file">The image file.</param>
        /// <param name="type">The type of check to make.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus QueryCodeIntegrityCertificateInfo(NtFile image_file, int type)
        {
            SystemCodeIntegrityCertificateInformation info = new SystemCodeIntegrityCertificateInformation()
            {
                ImageFile = image_file.Handle.DangerousGetHandle(),
                Type = type
            };

            return Query(SystemInformationClass.SystemCodeIntegrityCertificateInformation, info, false).Status;
        }

        /// <summary>
        /// Query the image path from a process ID.
        /// </summary>
        /// <param name="pid">The ID of the process.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The image path.</returns>
        /// <remarks>This method can be called without any permissions on the process.</remarks>
        public static NtResult<string> GetProcessIdImagePath(int pid, bool throw_on_error)
        {
            var info = new SystemProcessIdInformation() { ProcessId = new IntPtr(pid) };
            using (var buffer = info.ToBuffer())
            {
                NtStatus status = _system_info_object.QueryInformation(
                    SystemInformationClass.SystemProcessIdInformation, 
                    buffer, out int length);
                if (status.IsSuccess())
                {
                    return new NtResult<string>(NtStatus.STATUS_SUCCESS, string.Empty);
                }
                if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                {
                    return status.CreateResultFromError<string>(throw_on_error);
                }

                using (var str = new UnicodeStringAllocated(buffer.Result.ImageName.MaximumLength))
                {
                    info = new SystemProcessIdInformation() { ProcessId = new IntPtr(pid), ImageName = str.String };
                    return Query(SystemInformationClass.SystemProcessIdInformation, 
                        info, throw_on_error).Map(r => r.ImageName.ToString());
                }
            }
        }

        /// <summary>
        /// Query the image path from a process ID.
        /// </summary>
        /// <param name="pid">The ID of the process.</param>
        /// <returns>The image path.</returns>
        /// <remarks>This method can be called without any permissions on the process.</remarks>
        public static string GetProcessIdImagePath(int pid)
        {
            return GetProcessIdImagePath(pid, true).Result;
        }

        /// <summary>
        /// Get flags for isolated user mode.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The ISO flags.</returns>

        public static NtResult<SystemIsolatedUserModeInformationFlags> GetIsolatedUserModeFlags(bool throw_on_error)
        {
            return Query(SystemInformationClass.SystemIsolatedUserModeInformation, 
                default(SystemIsolatedUserModeInformation), throw_on_error).Map(s => s.Flags);
        }

        /// <summary>
        /// Query a fixed structure from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<T> Query<T>(SystemInformationClass info_class, T default_value, bool throw_on_error) where T : new()
        {
            return _system_info_object.Query(info_class, default_value, throw_on_error);
        }

        /// <summary>
        /// Query a fixed structure from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static T Query<T>(SystemInformationClass info_class, T default_value) where T : new()
        {
            return _system_info_object.Query(info_class, default_value);
        }

        /// <summary>
        /// Query a fixed structure from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static T Query<T>(SystemInformationClass info_class) where T : new()
        {
            return _system_info_object.Query<T>(info_class);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<SafeStructureInOutBuffer<T>> QueryBuffer<T>(SystemInformationClass info_class, T default_value, bool throw_on_error) where T : new()
        {
            return _system_info_object.QueryBuffer(info_class, default_value, throw_on_error);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="init_buffer">A buffer to initialize the initial query. Can be null.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<SafeHGlobalBuffer> QueryRawBuffer(SystemInformationClass info_class, byte[] init_buffer, bool throw_on_error)
        {
            return _system_info_object.QueryRawBuffer(info_class, init_buffer, throw_on_error);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="init_buffer">A buffer to initialize the initial query. Can be null.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static SafeHGlobalBuffer QueryRawBuffer(SystemInformationClass info_class, byte[] init_buffer)
        {
            return _system_info_object.QueryRawBuffer(info_class, init_buffer);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static SafeHGlobalBuffer QueryRawBuffer(SystemInformationClass info_class)
        {
            return _system_info_object.QueryRawBuffer(info_class);
        }

        /// <summary>
        /// Query a variable buffer from the object and return as bytes.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="init_buffer">A buffer to initialize the initial query. Can be null.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<byte[]> QueryRawBytes(SystemInformationClass info_class, byte[] init_buffer, bool throw_on_error)
        {
            return _system_info_object.QueryRawBytes(info_class, init_buffer, throw_on_error);
        }

        /// <summary>
        /// Query a variable buffer from the object and return as bytes.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="init_buffer">A buffer to initialize the initial query. Can be null.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static byte[] QueryRawBytes(SystemInformationClass info_class, byte[] init_buffer)
        {
            return _system_info_object.QueryRawBytes(info_class, init_buffer);
        }

        /// <summary>
        /// Query a variable buffer from the object and return as bytes.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static byte[] QueryRawBytes(SystemInformationClass info_class)
        {
            return _system_info_object.QueryRawBytes(info_class);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static SafeStructureInOutBuffer<T> QueryBuffer<T>(SystemInformationClass info_class, T default_value) where T : new()
        {
            return _system_info_object.QueryBuffer(info_class, default_value);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static SafeStructureInOutBuffer<T> QueryBuffer<T>(SystemInformationClass info_class) where T : new()
        {
            return _system_info_object.QueryBuffer<T>(info_class);
        }

        /// <summary>
        /// Set a value to the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to set.</typeparam>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="value">The value to set. If you specify a SafeBuffer then it'll be passed directly.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtStatus Set<T>(SystemInformationClass info_class, T value, bool throw_on_error) where T : struct
        {
            return _system_info_object.Set(info_class, value, throw_on_error);
        }

        /// <summary>
        /// Set a value to the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to set.</typeparam>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="value">The value to set.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static void Set<T>(SystemInformationClass info_class, T value) where T : struct
        {
            _system_info_object.Set(info_class, value);
        }

        /// <summary>
        /// Set a value to the object from a buffer.
        /// </summary>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="buffer">The value to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtStatus SetBuffer(SystemInformationClass info_class, SafeBuffer buffer, bool throw_on_error)
        {
            return _system_info_object.SetBuffer(info_class, buffer, throw_on_error);
        }

        /// <summary>
        /// Set a value to the object from a buffer..
        /// </summary>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="buffer">The value to set.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static void SetBuffer(SystemInformationClass info_class, SafeBuffer buffer)
        {
            _system_info_object.SetBuffer(info_class, buffer);
        }

        /// <summary>
        /// Set a raw value to the object.
        /// </summary>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="value">The raw value to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtStatus SetBytes(SystemInformationClass info_class, byte[] value, bool throw_on_error)
        {
            return _system_info_object.SetBytes(info_class, value, throw_on_error);
        }

        /// <summary>
        /// Set a raw value to the object.
        /// </summary>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="value">The raw value to set.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static void SetBytes(SystemInformationClass info_class, byte[] value)
        {
            _system_info_object.SetBytes(info_class, value);
        }

        /// <summary>
        /// Draw text on the background.
        /// </summary>
        /// <param name="text">The text to draw.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus DrawText(string text, bool throw_on_error)
        {
            return NtSystemCalls.NtDrawText(new UnicodeString(text)).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Draw text on the background.
        /// </summary>
        /// <param name="text">The text to draw.</param>
        public static void DrawText(string text)
        {
            DrawText(text, true);
        }

        /// <summary>
        /// Display a string.
        /// </summary>
        /// <param name="text">The text to display.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus DisplayString(string text, bool throw_on_error)
        {
            return NtSystemCalls.NtDisplayString(new UnicodeString(text)).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Display a string.
        /// </summary>
        /// <param name="text">The text to display.</param>
        public static void DisplayString(string text)
        {
            DisplayString(text, true);
        }

        /// <summary>
        /// Load a driver.
        /// </summary>
        /// <param name="driver_service_name">The name of the driver service.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus LoadDriver(string driver_service_name, bool throw_on_error = true)
        {
            return NtSystemCalls.NtLoadDriver(new UnicodeString(driver_service_name)).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Unload a driver.
        /// </summary>
        /// <param name="driver_service_name">The name of the driver service.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus UnloadDriver(string driver_service_name, bool throw_on_error = true)
        {
            return NtSystemCalls.NtUnloadDriver(new UnicodeString(driver_service_name)).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Get kernel modules.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of kernel modules.</returns>
        public static NtResult<IEnumerable<ProcessModule>> GetKernelModules(bool throw_on_error)
        {
            using (var buffer = QueryBuffer<RtlProcessModules>(SystemInformationClass.SystemModuleInformation, default, throw_on_error))
            {
                if (!buffer.IsSuccess)
                    return buffer.Cast<IEnumerable<ProcessModule>>();
                var result = buffer.Result.Result;
                ProcessModule[] modules = new ProcessModule[result.NumberOfModules];
                int size = Marshal.SizeOf(typeof(RtlProcessModuleInformation));
                IntPtr ptr = buffer.Result.Data.DangerousGetHandle();

                for (int i = 0; i < modules.Length; ++i)
                {
                    modules[i] = new ProcessModule((RtlProcessModuleInformation)Marshal.PtrToStructure(ptr, typeof(RtlProcessModuleInformation)));
                    ptr += size;
                }

                return modules.CreateResult<IEnumerable<ProcessModule>>();
            }
        }

        /// <summary>
        /// Get kernel modules.
        /// </summary>
        /// <returns>The list of kernel modules.</returns>
        public static IEnumerable<ProcessModule> GetKernelModules()
        {
            return GetKernelModules(true).Result;
        }

        #endregion

        #region Static Properties
        /// <summary>
        /// Get whether the kernel debugger is enabled.
        /// </summary>
        public static bool KernelDebuggerEnabled
        {
            get
            {
                return GetKernelDebuggerInformation().KernelDebuggerEnabled;
            }
        }

        /// <summary>
        /// Get whether the kernel debugger is not present.
        /// </summary>
        public static bool KernelDebuggerNotPresent
        {
            get
            {
                return GetKernelDebuggerInformation().KernelDebuggerNotPresent;
            }
        }

        /// <summary>
        /// Get current code integrity option settings.
        /// </summary>
        public static CodeIntegrityOptions CodeIntegrityOptions
        {
            get
            {
                return Query(SystemInformationClass.SystemCodeIntegrityInformation, 
                    new SystemCodeIntegrityInformation() { Length = Marshal.SizeOf(typeof(SystemCodeIntegrityInformation)) }).CodeIntegrityOptions;
            }
        }

        /// <summary>
        /// Get code integrity policy.
        /// </summary>
        public static SystemCodeIntegrityPolicy CodeIntegrityPolicy
        {
            get
            {
                return Query<SystemCodeIntegrityPolicy>(SystemInformationClass.SystemCodeIntegrityPolicyInformation);
            }
        }

        /// <summary>
        /// Get code integrity unlock information.
        /// </summary>
        public static int CodeIntegrityUnlock
        {
            get
            {
                return Query<int>(SystemInformationClass.SystemCodeIntegrityUnlockInformation);
            }
        }

        /// <summary>
        /// Get all code integrity policies.
        /// </summary>
        public static IEnumerable<CodeIntegrityPolicy> CodeIntegrityFullPolicy
        {
            get
            {
                List<CodeIntegrityPolicy> policies = new List<CodeIntegrityPolicy>();
                try
                {
                    MemoryStream stm = new MemoryStream(QueryRawBytes(SystemInformationClass.SystemCodeIntegrityPoliciesFullInformation));
                    if (stm.Length > 0)
                    {
                        BinaryReader reader = new BinaryReader(stm);
                        int header_size = reader.ReadInt32();
                        int total_policies = reader.ReadInt32();
                        reader.ReadBytes(8 - header_size);
                        for (int i = 0; i < total_policies; ++i)
                        {
                            policies.Add(new CodeIntegrityPolicy(reader));
                        }
                    }
                }
                catch (NtException)
                {
                    byte[] policy = QueryRawBytes(SystemInformationClass.SystemCodeIntegrityPolicyFullInformation);
                    if (policy.Length > 0)
                    {
                        policies.Add(new CodeIntegrityPolicy(policy));
                    }
                }

                return policies.AsReadOnly();
            }
        }

        /// <summary>
        /// Get whether secure boot is enabled.
        /// </summary>
        public static bool SecureBootEnabled
        {
            get
            {
                return Query<SystemSecurebootInformation>(SystemInformationClass.SystemSecureBootInformation).SecureBootEnabled;
            }
        }

        /// <summary>
        /// Get whether system supports secure boot.
        /// </summary>
        public static bool SecureBootCapable
        {
            get
            {
                return Query<SystemSecurebootInformation>(SystemInformationClass.SystemSecureBootInformation).SecureBootCapable;
            }
        }

        /// <summary>
        /// Extract the secure boot policy.
        /// </summary>
        public static SecureBootPolicy SecureBootPolicy
        {
            get
            {
                using (var buffer = QueryBuffer<SystemSecurebootPolicyFullInformation>(SystemInformationClass.SystemSecureBootPolicyFullInformation))
                {
                    return new SecureBootPolicy(buffer);
                }
            }
        }
        /// <summary>
        /// Get system timer resolution.
        /// </summary>
        public static int TimerResolution => GetBasicInfo().TimerResolution;
        /// <summary>
        /// Get system page size.
        /// </summary>
        public static int PageSize => GetBasicInfo().PageSize;
        /// <summary>
        /// Get number of physical pages.
        /// </summary>
        public static int NumberOfPhysicalPages => GetBasicInfo().NumberOfPhysicalPages;
        /// <summary>
        /// Get lowest page number.
        /// </summary>
        public static int LowestPhysicalPageNumber => GetBasicInfo().LowestPhysicalPageNumber;
        /// <summary>
        /// Get highest page number.
        /// </summary>
        public static int HighestPhysicalPageNumber => GetBasicInfo().HighestPhysicalPageNumber;
        /// <summary>
        /// Get allocation granularity.
        /// </summary>
        public static int AllocationGranularity => GetBasicInfo().AllocationGranularity;
        /// <summary>
        /// Get minimum user mode address.
        /// </summary>
        public static ulong MinimumUserModeAddress => GetBasicInfo().MinimumUserModeAddress.ToUInt64();
        /// <summary>
        /// Get maximum user mode address.
        /// </summary>
        public static ulong MaximumUserModeAddress => GetBasicInfo().MaximumUserModeAddress.ToUInt64();
        /// <summary>
        /// Get active processor affinity mask.
        /// </summary>
        public static ulong ActiveProcessorsAffinityMask => GetBasicInfo().ActiveProcessorsAffinityMask.ToUInt64();
        /// <summary>
        /// Get number of processors.
        /// </summary>
        public static int NumberOfProcessors => GetBasicInfo().NumberOfProcessors;
        /// <summary>
        /// Get system device information.
        /// </summary>
        public static SystemDeviceInformation DeviceInformation => Query<SystemDeviceInformation>(SystemInformationClass.SystemDeviceInformation);
        /// <summary>
        /// Get the system processor information.
        /// </summary>
        public static SystemProcessorInformation ProcessorInformation => QueryCached<SystemProcessorInformation>(SystemInformationClass.SystemProcessorInformation);
        /// <summary>
        /// Get the system emulation processor information.
        /// </summary>
        public static SystemProcessorInformation EmulationProcessorInformation => QueryCached<SystemProcessorInformation>(SystemInformationClass.SystemEmulationProcessorInformation);
        /// <summary>
        /// Get the Isolated User Mode flags.
        /// </summary>
        public static SystemIsolatedUserModeInformationFlags IsolatedUserModeFlags => GetIsolatedUserModeFlags(true).Result;

        #endregion
    }
}
