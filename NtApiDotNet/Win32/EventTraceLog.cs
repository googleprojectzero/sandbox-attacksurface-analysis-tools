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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Level for trace event.
    /// </summary>
    public enum EventTraceLevel : byte
    {
        /// <summary>
        /// Critical level.
        /// </summary>
        Critical = 1,
        /// <summary>
        /// Error level.
        /// </summary>
        Error = 2,
        /// <summary>
        /// Warning level.
        /// </summary>
        Warning = 3,
        /// <summary>
        /// Information level.
        /// </summary>
        Information = 4,
        /// <summary>
        /// Verbose level.
        /// </summary>
        Verbose = 5,
    }

    /// <summary>
    /// An Event Trace Log.
    /// </summary>
    public sealed class EventTraceLog : IDisposable
    {
        private readonly long _handle;
        private readonly SafeBuffer _properties;

        internal EventTraceLog(long handle, Guid session_guid, string session_name, SafeHGlobalBuffer properties)
        {
            _handle = handle;
            SessionGuid = session_guid;
            SessionName = session_name;
            _properties = properties.Detach();
        }

        /// <summary>
        /// Get allocated session GUID.
        /// </summary>
        public Guid SessionGuid { get; }

        /// <summary>
        /// Get name of the session.
        /// </summary>
        public string SessionName { get; }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        private void Dispose(bool disposing)
        {
            if (!disposedValue && !_properties.IsClosed)
            {
                disposedValue = true;
                var status = Win32NativeMethods.ControlTrace(_handle, null,
                    _properties, EventTraceControl.Stop);
                System.Diagnostics.Debug.WriteLine($"{status}");
                _properties?.Dispose();
            }
        }

        /// <summary>
        /// Finalizer.
        /// </summary>
         ~EventTraceLog()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the event trace log.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
