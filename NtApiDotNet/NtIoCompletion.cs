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
    /// <summary>
    /// Class representing an NT IO Completion Port object
    /// </summary>
    [NtType("IoCompletion")]
    public class NtIoCompletion : NtObjectWithDuplicateAndInfo<NtIoCompletion, IoCompletionAccessRights, IoCompletionInformationClass, IoCompletionInformationClass>
    {
        #region Constructors

        internal NtIoCompletion(SafeKernelObjectHandle handle) 
            : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtIoCompletion> OpenInternal(ObjectAttributes obj_attributes,
                IoCompletionAccessRights desired_access, bool throw_on_error)
            {
                return NtIoCompletion.Open(obj_attributes, desired_access, throw_on_error);
            }
        }

        #endregion

        #region Static Methods

        /// <summary>
        /// Create an IO Completion Port object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">The desired access for the event</param>
        /// <param name="concurrent_threads">Number of concurrent threads to process I/O packets. 0 for CPU count.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtIoCompletion> Create(ObjectAttributes object_attributes, IoCompletionAccessRights desired_access, int concurrent_threads, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            return NtSystemCalls.NtCreateIoCompletion(out handle, desired_access, object_attributes, concurrent_threads).CreateResult(throw_on_error, () => new NtIoCompletion(handle));
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
            return Create(object_attributes, desired_access, concurrent_threads, true).Result;
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
            return Open(object_attributes, desired_access, true).Result;
        }

        /// <summary>
        /// Open an IO Completion Port object
        /// </summary>
        /// <param name="object_attributes">The object attributes</param>
        /// <param name="desired_access">The desired access for the event</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtResult<NtIoCompletion> Open(ObjectAttributes object_attributes, IoCompletionAccessRights desired_access, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            return NtSystemCalls.NtOpenIoCompletion(out handle, desired_access, object_attributes).CreateResult(throw_on_error, () => new NtIoCompletion(handle));
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
        #endregion

        #region Public Methods

        /// <summary>
        /// Remove a queued status from the queue.
        /// </summary>
        /// <param name="timeout">An optional timeout.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The completion result.</returns>
        /// <exception cref="NtException">Thrown on error or timeout.</exception>
        public NtResult<FileIoCompletionResult> Remove(NtWaitTimeout timeout, bool throw_on_error)
        {
            var io_status = new IoStatus();
            return NtSystemCalls.NtRemoveIoCompletion(Handle, out IntPtr key_context,
                out IntPtr apc_context, io_status, timeout.ToLargeInteger())
                .CreateResult(throw_on_error, () => new FileIoCompletionResult(key_context, apc_context, io_status));
        }

        /// <summary>
        /// Remove a queued status from the queue.
        /// </summary>
        /// <param name="timeout">An optional timeout.</param>
        /// <returns>The completion result.</returns>
        /// <exception cref="NtException">Thrown on error or timeout.</exception>
        public FileIoCompletionResult Remove(NtWaitTimeout timeout)
        {
            return Remove(timeout, true).Result;
        }

        /// <summary>
        /// Remove multiple queued status from the queue.
        /// </summary>
        /// <param name="max_count">Maximum number of status to remove.</param>
        /// <param name="timeout">An optional timeout.</param>
        /// <param name="alertable">Indicate whether the wait is alertable.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>Array of completion results. Length can be &lt;= max_count.</returns>
        public NtResult<FileIoCompletionResult[]> Remove(int max_count, NtWaitTimeout timeout, bool alertable, bool throw_on_error)
        {
            IoStatus io_status = new IoStatus();
            FileIoCompletionInformation[] result = new FileIoCompletionInformation[max_count];

            return NtSystemCalls.NtRemoveIoCompletionEx(Handle, result, max_count,
                out int result_count, timeout.ToLargeInteger(), alertable).CreateResult(throw_on_error, () =>
                result.Take(result_count).Select(r => new FileIoCompletionResult(r)).ToArray());
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
            return Remove(max_count, timeout, alertable, false).GetResultOrDefault(new FileIoCompletionResult[0]);
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
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public override NtStatus QueryInformation(IoCompletionInformationClass info_class, SafeBuffer buffer, out int return_length)
        {
            return NtSystemCalls.NtQueryIoCompletion(Handle, info_class,
                        buffer, (int)buffer.ByteLength, out return_length);
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get current depth of IO Completion Port
        /// </summary>
        public int Depth
        {
            get
            {
                return Query<IoCompletionBasicInformation>(IoCompletionInformationClass.IoCompletionBasicInformation).Depth;
            }
        }
        #endregion
    }
}
