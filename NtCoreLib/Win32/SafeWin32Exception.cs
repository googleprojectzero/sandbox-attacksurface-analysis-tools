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
using System.ComponentModel;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Represents an impersonation safe win32 exception, which resolves the win32 message when Message is called.
    /// </summary>
    [Serializable]
    public class SafeWin32Exception : Win32Exception
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public SafeWin32Exception()
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="error">Win32 error.</param>
        public SafeWin32Exception(int error) : base(error)
        {
        }

        internal SafeWin32Exception(Win32Error error) 
            : this((int)error)
        {
        }

        /// <summary>
        /// The message for the exception.
        /// </summary>
        public override string Message
        {
            get
            {
                Win32Exception e = new Win32Exception(NativeErrorCode);
                return e.Message;
            }
        }
    }
}
