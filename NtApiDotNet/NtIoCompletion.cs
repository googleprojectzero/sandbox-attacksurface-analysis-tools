//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum IoCompletionAccessRights : uint
    {
        QueryState = 1,
        SetCompletion = 2,
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

    [StructLayout(LayoutKind.Sequential)]
    public struct FileIoCompletionInformation
    {
        public IntPtr KeyContext;
        public IntPtr ApcContext;
        public IoStatusStruct IoStatusBlock;
    }

    public class FileIoCompletionResult
    {
        public IntPtr KeyContext { get; private set; }
        public IntPtr ApcContext { get; private set; }
        public IoStatus IoStatusBlock { get; private set; }

        internal FileIoCompletionResult(FileIoCompletionInformation result)
        {
            KeyContext = result.KeyContext;
            ApcContext = result.ApcContext;
            IoStatusBlock = new IoStatus()
            {
                Information = result.IoStatusBlock.Information,
                Pointer = result.IoStatusBlock.Pointer
            };
        }

        internal FileIoCompletionResult(IntPtr key_context, IntPtr apc_context, IoStatus io_status)
        {
            KeyContext = key_context;
            ApcContext = apc_context;
            IoStatusBlock = io_status;
        }
        
    }

    public enum IoCompletionInformationClass
    {
        IoCompletionBasicInformation
    }

    public struct IoCompletionBasicInformation
    {
        public int Depth;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateIoCompletion(
            out SafeKernelObjectHandle IoCompletionHandle,
            IoCompletionAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            int NumberOfConcurrentThreads
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenIoCompletion(
            out SafeKernelObjectHandle IoCompletionHandle,
            IoCompletionAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRemoveIoCompletion(
            SafeKernelObjectHandle IoCompletionHandle,
            out IntPtr KeyContext,
            out IntPtr ApcContext,
            [In, Out] IoStatus IoStatusBlock,
            LargeInteger Timeout
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRemoveIoCompletionEx(
            SafeKernelObjectHandle IoCompletionHandle,
            [Out] FileIoCompletionInformation[] IoCompletionInformation,
            int InformationCount,
            out int NumEntriesRemoved,
            [In] LargeInteger Timeout,
            bool Alertable
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryIoCompletion(
            SafeKernelObjectHandle IoCompletionHandle,
            IoCompletionInformationClass IoCompletionInformationClass,
            SafeBuffer IoCompletionInformation,
            int IoCompletionInformationLength,
            OptionalInt32 ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetIoCompletion(
            SafeKernelObjectHandle IoCompletionHandle,
            IntPtr KeyContext,
            IntPtr ApcContext,
            NtStatus Status,
            IntPtr IoStatusInformation
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetIoCompletionEx(
            SafeKernelObjectHandle IoCompletionHandle,
            SafeKernelObjectHandle IoCompletionPacketHandle,
            IntPtr KeyContext,
            IntPtr ApcContext,
            NtStatus IoStatus,
            IntPtr IoStatusInformation
        );
    }

#pragma warning restore 1591

    /// <summary>
    /// Class representing an NT IO Completion Port object
    /// </summary>
    public class NtIoCompletion : NtObjectWithDuplicate<NtIoCompletion, IoCompletionAccessRights>
    {
        internal NtIoCompletion(SafeKernelObjectHandle handle) 
            : base(handle)
        {
        }

        /// <summary>
        /// Create an IO Completion Port object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">The desired access for the event</param>
        /// <param name="concurrent_threads">Number of concurrent threads to process I/O packets. 0 for CPU count.</param>
        /// <returns>The IO Completion Port object.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtIoCompletion Create(ObjectAttributes object_attributes, IoCompletionAccessRights desired_access, int concurrent_threads)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtCreateIoCompletion(out handle, desired_access, object_attributes, concurrent_threads).ToNtException();
            return new NtIoCompletion(handle);
        }

        /// <summary>
        /// Create an IO Completion Port object
        /// </summary>
        /// <param name="name">The path to the IO Completion Port</param>
        /// <param name="root">The root object for relative path names</param>
        /// <param name="desired_access">The desired access for the event</param>
        /// <param name="concurrent_threads">Number of concurrent threads to process I/O packets. 0 for CPU count.</param>
        /// <returns>The IO Completion Port object.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtIoCompletion Create(string name, NtObject root, IoCompletionAccessRights desired_access, int concurrent_threads)
        {
            using (ObjectAttributes obj_attr = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obj_attr, desired_access, concurrent_threads);
            }
        }

        /// <summary>
        /// Create an unnamed IO Completion Port object.
        /// </summary>
        /// <returns>The IO Completion Port object.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtIoCompletion Create()
        {
            return Create(null, IoCompletionAccessRights.MaximumAllowed, 0);
        }

        /// <summary>
        /// Open an IO Completion Port object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">The desired access for the event</param>
        /// <returns>The IO Completion Port object.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtIoCompletion Open(ObjectAttributes object_attributes, IoCompletionAccessRights desired_access)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtOpenIoCompletion(out handle, desired_access, object_attributes).ToNtException();
            return new NtIoCompletion(handle);
        }

        /// <summary>
        /// Open an IO Completion Port object
        /// </summary>
        /// <param name="name">The path to the IO Completion Port</param>
        /// <param name="root">The root object for relative path names</param>
        /// <param name="desired_access">The desired access for the event</param>
        /// <returns>The IO Completion Port object.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtIoCompletion Open(string name, NtObject root, IoCompletionAccessRights desired_access)
        {
            using (ObjectAttributes obj_attr = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obj_attr, desired_access);
            }
        }

        /// <summary>
        /// Open an IO Completion Port object
        /// </summary>
        /// <param name="name">The path to the IO Completion Port</param>
        /// <returns>The IO Completion Port object.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtIoCompletion Open(string name)
        {
            return Open(name, null, IoCompletionAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Remove a queued status from the queue.
        /// </summary>
        /// <param name="timeout">An optional timeout.</param>
        /// <returns>The completion result.</returns>
        /// <exception cref="NtException">Thrown on error or timeout.</exception>
        public FileIoCompletionResult Remove(NtWaitTimeout timeout)
        {
            IntPtr key_context;
            IntPtr apc_context;
            IoStatus io_status = new IoStatus();
            NtStatus status = NtSystemCalls.NtRemoveIoCompletion(Handle, out key_context, out apc_context, io_status, timeout.Timeout).ToNtException();
            if (status != NtStatus.STATUS_SUCCESS)
            {
                throw new NtException(status);
            }
            return new FileIoCompletionResult(key_context, apc_context, io_status);
        }

        /// <summary>
        /// Remove multiple queued status from the queue.
        /// </summary>
        /// <param name="max_count">Maximum number of status to remove.</param>
        /// <param name="timeout">An optional timeout.</param>
        /// <param name="alertable">Indicate whether the wait is alertable.</param>
        /// <returns>Array of completion results. Length can be &lt;= max_count. If timeout then returns an empty array.</returns>
        public FileIoCompletionResult[] Remove(int max_count, NtWaitTimeout timeout, bool alertable)
        {
            IoStatus io_status = new IoStatus();
            FileIoCompletionInformation[] result = new FileIoCompletionInformation[max_count];
            int result_count = 0;

            NtStatus status = NtSystemCalls.NtRemoveIoCompletionEx(Handle, result, max_count,
                out result_count, timeout.Timeout, alertable).ToNtException();
            if (status == NtStatus.STATUS_SUCCESS)
            {
                return result.Take(result_count).Select(r => new FileIoCompletionResult(r)).ToArray();
            }
            return new FileIoCompletionResult[0];
        }

        /// <summary>
        /// Remove multiple queued status from the queue.
        /// </summary>
        /// <param name="max_count">Maximum number of status to remove.</param>
        /// <returns>Array of completion results. Length can be &lt;= max_count</returns>
        public FileIoCompletionResult[] Remove(int max_count)
        {
            return Remove(max_count, NtWaitTimeout.Infinite, false);
        }

        /// <summary>
        /// Remove a queued status from the queue. Wait for an infinite time for the result.
        /// </summary>
        /// <returns>The completion result.</returns>
        public FileIoCompletionResult Remove()
        {
            return Remove(NtWaitTimeout.Infinite);
        }

        /// <summary>
        /// Add a queued status to the queue.
        /// </summary>
        /// <param name="key_context">The optional key context.</param>
        /// <param name="apc_context">The optional APC context.</param>
        /// <param name="status">Status code</param>
        /// <param name="information">The information context.</param>
        public void Set(IntPtr key_context, IntPtr apc_context, NtStatus status, IntPtr information)
        {
            NtSystemCalls.NtSetIoCompletion(Handle, key_context, 
                apc_context, status, information).ToNtException();
        }

        /// <summary>
        /// Get current depth of IO Completion Port
        /// </summary>
        public int Depth
        {
            get
            {
                using (var buffer = new SafeStructureInOutBuffer<IoCompletionBasicInformation>())
                {
                    NtSystemCalls.NtQueryIoCompletion(Handle, IoCompletionInformationClass.IoCompletionBasicInformation,
                        buffer, buffer.Length, null).ToNtException();
                    return buffer.Result.Depth;
                }
            }
        }
    }
}
