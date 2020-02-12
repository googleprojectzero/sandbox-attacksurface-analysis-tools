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
using System.Collections.Generic;
using System.Linq;
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
    /// Descriptor for an enabled trace provider.
    /// </summary>
    public struct EventFilterDescriptor
    {
        /// <summary>
        /// Pointer to descriptor data.
        /// </summary>
        public IntPtr Ptr { get; set; }
        /// <summary>
        /// Size of descriptor data.
        /// </summary>
        public int Size { get; set; }
        /// <summary>
        /// Type of descriptor data.
        /// </summary>
        public int Type { get; set; }
    }

    /// <summary>
    /// An Event Trace Log.
    /// </summary>
    public sealed class EventTraceLog : IDisposable
    {
        private struct EnabledProvider
        {
            public Guid ProviderId;
            public EventTraceLevel Level;
        }

        private readonly long _handle;
        private readonly SafeBuffer _properties;
        private readonly List<EnabledProvider> _providers;

        internal EventTraceLog(long handle, Guid session_guid, string session_name, SafeHGlobalBuffer properties)
        {
            _handle = handle;
            SessionGuid = session_guid;
            SessionName = session_name;
            _properties = properties.Detach();
            _providers = new List<EnabledProvider>();
        }

        /// <summary>
        /// Enable a provider.
        /// </summary>
        /// <param name="provider_id">The GUID of the provider.</param>
        /// <param name="level">The level for the events.</param>
        /// <param name="match_any_keyword">Any keywords to match.</param>
        /// <param name="match_all_keyword">All keywords to match.</param>
        /// <param name="timeout">The timeout.</param>
        /// <param name="descriptors">List of optional descriptors.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The resulting status code.</returns>
        public NtStatus EnableProvider(Guid provider_id, EventTraceLevel level, ulong match_any_keyword,
          ulong match_all_keyword, int timeout, IEnumerable<EventFilterDescriptor> descriptors, bool throw_on_error)
        {
            var ds = descriptors.Select(d => new EVENT_FILTER_DESCRIPTOR()
            {
                Ptr = d.Ptr.ToInt64(),
                Size = d.Size,
                Type = d.Type
            }).ToArray();

            using (var buffer = ds.ToBuffer())
            {
                ENABLE_TRACE_PARAMETERS enable_trace = new ENABLE_TRACE_PARAMETERS
                {
                    Version = 2,
                    SourceId = SessionGuid,
                    EnableFilterDesc = buffer.DangerousGetHandle(),
                    FilterDescCount = ds.Length
                };

                NtStatus status = Win32NativeMethods.EnableTraceEx2(
                    _handle,
                    ref provider_id,
                    EventControlCode.EnableProvider,
                    level,
                    match_any_keyword,
                    match_all_keyword,
                    timeout,
                    enable_trace
                ).MapDosErrorToStatus().ToNtException(throw_on_error);
                if (status.IsSuccess())
                {
                    _providers.Add(new EnabledProvider() { ProviderId = provider_id, Level = level });
                }
                return status;
            }
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

                if (_providers.Count > 0)
                {
                    foreach (var prov in _providers)
                    {
                        Guid provider_id = prov.ProviderId;
                        Win32NativeMethods.EnableTraceEx2(_handle, ref provider_id, 
                            EventControlCode.DisableProvider, prov.Level, 0, 0, 0, null);
                    }
                }

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
