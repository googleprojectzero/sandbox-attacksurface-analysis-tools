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

namespace NtApiDotNet.Win32.Filter
{
    /// <summary>
    /// Class to represent a filter communications port message.
    /// </summary>
    public class FilterConnectionPortMessage
    {
        /// <summary>
        /// The message ID.
        /// </summary>
        public ulong MessageId { get; }
        /// <summary>
        /// The returned data.
        /// </summary>
        public byte[] Data { get; }
        /// <summary>
        /// The length of the reply to send.
        /// </summary>
        public int ReplyLength { get; }

        internal FilterConnectionPortMessage(SafeStructureInOutBuffer<FILTER_MESSAGE_HEADER> buffer)
        {
            var result = buffer.Result;
            MessageId = result.MessageId;
            ReplyLength = result.ReplyLength;
            Data = buffer.Data.ToArray();
        }
    }
}
