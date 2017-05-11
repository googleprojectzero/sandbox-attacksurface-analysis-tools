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

namespace NtApiDotNet
{
    /// <summary>
    /// Exception class representing an NT status error.
    /// </summary>
    [Serializable]
    public sealed class NtException : ApplicationException
    {
        private NtStatus _status;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="status">Status result</param>
        public NtException(NtStatus status) 
        {
            _status = status;
        }

        /// <summary>
        /// Returns the contained NT status code
        /// </summary>
        public NtStatus Status { get { return _status; } }

        /// <summary>
        /// Returns a string form of the NT status code.
        /// </summary>
        public override string Message
        {
            get
            {
                string message = NtObjectUtils.GetNtStatusMessage(_status);
                if (String.IsNullOrEmpty(message))
                {
                    if (Enum.IsDefined(typeof(NtStatus), _status))
                    {
                        message = _status.ToString();
                    }
                    else
                    {
                        message = "Unknown NTSTATUS";
                    }
                }

                return String.Format("(0x{0:X08}) - {1}", (uint)_status, message);
            }
        }
    }

}
