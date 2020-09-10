//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Filter
{
    /// <summary>
    /// A class to represent filter communication port.
    /// </summary>
    public class FilterConnectionPort : NtFile
    {
        #region Constructors
        internal FilterConnectionPort(SafeKernelObjectHandle handle) 
            : base(handle)
        {
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Open a filter communications port.
        /// </summary>
        /// <param name="port_name">The port name, e.g. \FilterName</param>
        /// <param name="sync_handle">Make the handle synchronous.</param>
        /// <param name="context">Optional context data.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The filter communications port.</returns>
        public static NtResult<FilterConnectionPort> Open(string port_name, bool sync_handle, byte[] context, bool throw_on_error)
        {
            return FilterManagerNativeMethods.FilterConnectCommunicationPort(port_name, sync_handle ? FilterConnectFlags.FLT_PORT_FLAG_SYNC_HANDLE : 0,
                context, (short)(context?.Length ?? 0), null, out SafeKernelObjectHandle handle).CreateResult(throw_on_error, () => new FilterConnectionPort(handle));
        }

        /// <summary>
        /// Open a filter communications port.
        /// </summary>
        /// <param name="port_name">The port name, e.g. \FilterName</param>
        /// <param name="sync_handle">Make the handle synchronous.</param>
        /// <param name="context">Optional context data.</param>
        /// <returns>The filter communications port.</returns>
        public static FilterConnectionPort Open(string port_name, bool sync_handle, byte[] context)
        {
            return Open(port_name, sync_handle, context, true).Result;
        }

        /// <summary>
        /// Open a filter communications port.
        /// </summary>
        /// <param name="port_name">The port name, e.g. \FilterName</param>
        /// <returns>The filter communications port.</returns>
        public static FilterConnectionPort Open(string port_name)
        {
            return Open(port_name, false, null);
        }
        #endregion

        #region Public Methods

        /// <summary>
        /// Get message from port.
        /// </summary>
        /// <param name="max_message_size">The maximum message size to receive.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The returned message.</returns>
        public NtResult<FilterConnectionPortMessage> GetMessage(int max_message_size, bool throw_on_error)
        {
            using (var buffer = new SafeStructureInOutBuffer<FILTER_MESSAGE_HEADER>(max_message_size, true))
            {
                return FilterManagerNativeMethods.FilterGetMessage(Handle, buffer, 
                    buffer.Length, IntPtr.Zero).CreateResult(throw_on_error, 
                    () => new FilterConnectionPortMessage(buffer));
            }
        }

        /// <summary>
        /// Get message from port.
        /// </summary>
        /// <param name="max_message_size">The maximum message size to receive.</param>
        /// <returns>The returned message.</returns>
        public FilterConnectionPortMessage GetMessage(int max_message_size)
        {
            return GetMessage(max_message_size, true).Result;
        }

        /// <summary>
        /// Reply to message.
        /// </summary>
        /// <param name="status">The NT status code.</param>
        /// <param name="message_id">The message ID from GetMessage.</param>
        /// <param name="data">The data to send.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus ReplyMessage(NtStatus status, ulong message_id, byte[] data, bool throw_on_error)
        {
            FILTER_REPLY_HEADER header = new FILTER_REPLY_HEADER()
            {
                MessageId = message_id,
                Status = status
            };

            using (var buffer = header.ToBuffer(data.Length, true))
            {
                buffer.Data.WriteBytes(data);
                return FilterManagerNativeMethods.FilterReplyMessage(Handle, buffer, buffer.Length).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Reply to message.
        /// </summary>
        /// <param name="status">The NT status code.</param>
        /// <param name="message_id">The message ID from GetMessage.</param>
        /// <param name="data">The data to send.</param>
        public void ReplyMessage(NtStatus status, ulong message_id, byte[] data)
        {
            ReplyMessage(status, message_id, data, true);
        }

        /// <summary>
        /// Send a message to the filter.
        /// </summary>
        /// <param name="input">The input buffer.</param>
        /// <param name="output">The output buffer.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The bytes in the output buffer.</returns>
        public NtResult<int> SendMessage(SafeBuffer input, SafeBuffer output, bool throw_on_error)
        {
            return FilterManagerNativeMethods.FilterSendMessage(Handle, input ?? SafeHGlobalBuffer.Null,
                input?.GetLength() ?? 0, output ?? SafeHGlobalBuffer.Null, output?.GetLength() ?? 0,
                out int bytes_returned).CreateResult(throw_on_error, () => bytes_returned);
        }

        /// <summary>
        /// Send a message to the filter.
        /// </summary>
        /// <param name="input">The input buffer.</param>
        /// <param name="output">The output buffer.</param>
        /// <returns>The bytes in the output buffer.</returns>
        public int SendMessage(SafeBuffer input, SafeBuffer output)
        {
            return SendMessage(input, output, true).Result;
        }

        /// <summary>
        /// Send a message to the filter.
        /// </summary>
        /// <param name="input">The input buffer.</param>
        /// <param name="max_output_length">The maximum size of the output buffer.</param>
        /// <param name="throw_on_error">true to throw on error.</param>
        /// <returns>The output buffer.</returns>
        public NtResult<byte[]> SendMessage(byte[] input, int max_output_length, bool throw_on_error)
        {
            using (var input_buffer = input?.ToBuffer())
            {
                using (var output_buffer = new SafeHGlobalBuffer(max_output_length))
                {
                    return SendMessage(input_buffer, output_buffer, throw_on_error).Map(i => output_buffer.ReadBytes(i));
                }
            }
        }

        /// <summary>
        /// Send a message to the filter.
        /// </summary>
        /// <param name="input">The input buffer.</param>
        /// <param name="max_output_length">The maximum size of the output buffer.</param>
        /// <returns>The output buffer.</returns>
        public byte[] SendMessage(byte[] input, int max_output_length)
        {
            return SendMessage(input, max_output_length, true).Result;
        }

        #endregion
    }
}
