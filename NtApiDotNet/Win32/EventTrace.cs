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

using System;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Simple class for an event trace.
    /// </summary>
    public sealed class EventTrace : IDisposable
    {
        private readonly long _handle;

        internal EventTrace(long handle)
        {
            _handle = handle;
        }

        /// <summary>
        /// Write an empty event.
        /// </summary>
        public void Write()
        {
            EVENT_DESCRIPTOR desc = new EVENT_DESCRIPTOR()
            {
                Id = 1,
                Level = 4
            };
            Win32NativeMethods.EventWrite(_handle, ref desc, 0, null).ToNtException();
        }

        /// <summary>
        /// Dispose method.
        /// </summary>
        public void Dispose()
        {
            Win32NativeMethods.EventUnregister(_handle);
        }
    }
}
