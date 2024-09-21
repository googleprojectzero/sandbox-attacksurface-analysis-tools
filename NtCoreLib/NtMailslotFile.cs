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

namespace NtApiDotNet
{
    /// <summary>
    /// Class representing a NT File Mailslot client object
    /// </summary>
    public class NtMailslotFile : NtFile
    {
        #region Constructors
        internal NtMailslotFile(SafeKernelObjectHandle handle, IoStatus io_status) 
            : base(handle, io_status)
        {
        }
        #endregion

        #region Private Members
        private NtResult<FileMailslotQueryInformation> QueryInfo(bool throw_on_error)
        {
            return Query<FileMailslotQueryInformation>(FileInformationClass.FileMailslotQueryInformation, default, throw_on_error);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Set the mailslot read timeout.
        /// </summary>
        /// <param name="timeout">The timeout to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT Status code.</returns>
        public NtStatus SetReadTimeout(NtWaitTimeout timeout, bool throw_on_error)
        {
            LargeInteger read_timeout = timeout?.Timeout ?? new LargeInteger(-1);

            FileMailslotSetInformation set_info = new FileMailslotSetInformation()
            {
                ReadTimeout = read_timeout.ToStruct()
            };

            return Set(FileInformationClass.FileMailslotSetInformation, set_info, throw_on_error);
        }

        /// <summary>
        /// Peek on the current status of the Mailslot.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The peek status.</returns>
        public NtResult<FileMailslotPeekBuffer> Peek(bool throw_on_error)
        {
            using (var buffer = new SafeStructureInOutBuffer<FileMailslotPeekBuffer>())
            {
                return FsControl(NtWellKnownIoControlCodes.FSCTL_MAILSLOT_PEEK, buffer, buffer, throw_on_error).Map(_ => buffer.Result);
            }
        }

        /// <summary>
        /// Peek on the current status of the Mailslot.
        /// </summary>
        /// <returns>The peek status.</returns>
        public FileMailslotPeekBuffer Peek()
        {
            return Peek(true).Result;
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get or set the Read Timeout.
        /// </summary>
        public NtWaitTimeout ReadTimeout
        {
            get => QueryInfo(true).Result.ReadTimeout.ToTimeout();
            set => SetReadTimeout(value, true);
        }

        /// <summary>
        /// Get maximum message size.
        /// </summary>
        public int MaximumMessageSize => QueryInfo(true).Result.MaximumMessageSize;

        /// <summary>
        /// Get mailslot quota.
        /// </summary>
        public int MailslotQuota => QueryInfo(true).Result.MailslotQuota;

        /// <summary>
        /// Get next message size.
        /// </summary>
        public int NextMessageSize => QueryInfo(true).Result.NextMessageSize;

        /// <summary>
        /// Get messages available.
        /// </summary>
        public int MessagesAvailable => QueryInfo(true).Result.MessagesAvailable;

        #endregion
    }
}
