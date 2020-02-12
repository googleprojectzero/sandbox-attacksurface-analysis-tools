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

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Class to access event tracing methods.
    /// </summary>
    public static class EventTracing
    {
        /// <summary>
        /// Query security of an event.
        /// </summary>
        /// <param name="guid">The event GUID to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The event security descriptor.</returns>
        public static NtResult<SecurityDescriptor> QueryTraceSecurity(Guid guid, bool throw_on_error)
        {
            int length = 0;
            Win32Error error = Win32NativeMethods.EventAccessQuery(ref guid, SafeHGlobalBuffer.Null, ref length);
            if (error == Win32Error.ERROR_FILE_NOT_FOUND && guid != TraceKnownGuids.DefaultTraceSecurity)
            {
                return QueryTraceSecurity(TraceKnownGuids.DefaultTraceSecurity, throw_on_error);
            }

            if (error != Win32Error.ERROR_MORE_DATA)
            {
                return error.CreateResultFromDosError<SecurityDescriptor>(throw_on_error);
            }

            using (var buffer = new SafeHGlobalBuffer(length))
            {
                error = Win32NativeMethods.EventAccessQuery(ref guid, buffer, ref length);
                if (error != Win32Error.SUCCESS)
                {
                    return error.CreateResultFromDosError<SecurityDescriptor>(throw_on_error);
                }
                return SecurityDescriptor.Parse(buffer, NtType.GetTypeByType<NtEtwRegistration>(), throw_on_error);
            }
        }

        /// <summary>
        /// Query the default security for events.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The default security descriptor.</returns>
        public static NtResult<SecurityDescriptor> QueryDefaultSecurity(bool throw_on_error)
        {
            return QueryTraceSecurity(TraceKnownGuids.DefaultTraceSecurity, throw_on_error);
        }

        /// <summary>
        /// Register an event trace with a specific GUID.
        /// </summary>
        /// <param name="guid">The event trace GUID.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The event trace.</returns>
        public static NtResult<EventTrace> Register(Guid guid, bool throw_on_error)
        {
            return Win32NativeMethods.EventRegister(ref guid, null, IntPtr.Zero, out long handle)
                .MapDosErrorToStatus().CreateResult(throw_on_error, () => new EventTrace(handle));
        }

        /// <summary>
        /// Start an event trace log.
        /// </summary>
        /// <param name="logfile">The path to the log file.</param>
        /// <param name="session_guid">Session GUID.</param>
        /// <param name="session_name">The name of the logging session.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The event trace log.</returns>
        public static NtResult<EventTraceLog> Start(string logfile, Guid session_guid, string session_name, bool throw_on_error)
        {
            EVENT_TRACE_PROPERTIES properties = new EVENT_TRACE_PROPERTIES();
            properties.Wnode.Flags = WNodeFlags.TracedGuid;
            properties.Wnode.ClientContext = WNodeClientContext.QPC;
            properties.Wnode.Guid = session_guid;
            properties.LogFileMode = LogFileModeFlags.Sequential;
            properties.MaximumFileSize = 1;
            
            using (var buffer = properties.ToBuffer(logfile, session_name))
            {
                return Win32NativeMethods.StartTrace(out long handle, session_name, buffer).
                    MapDosErrorToStatus().CreateResult(throw_on_error, () 
                    => new EventTraceLog(handle, session_guid, session_name, buffer));
            }
        }

        /// <summary>
        /// Start an event trace log.
        /// </summary>
        /// <param name="logfile">The path to the log file.</param>
        /// <param name="session_guid">Session GUID.</param>
        /// <param name="session_name">The name of the logging session.</param>
        /// <returns>The event trace log.</returns>
        public static EventTraceLog Start(string logfile, Guid session_guid, string session_name)
        {
            return Start(logfile, session_guid, session_name, true).Result;
        }

        /// <summary>
        /// Register an event trace with a specific GUID.
        /// </summary>
        /// <param name="guid">The event trace GUID.</param>
        /// <returns>The event trace.</returns>
        public static EventTrace Register(Guid guid)
        {
            return Register(guid, true).Result;
        }

        /// <summary>
        /// Get the list of registered trace GUIDs.
        /// </summary>
        /// <returns>The list of trace GUIDs.</returns>
        public static IEnumerable<Guid> GetTraceGuids()
        {
            int curr_length = 1024;
            while (true)
            {
                using (var buffer = new SafeHGlobalBuffer(curr_length))
                {
                    Win32Error error = Win32NativeMethods.EnumerateTraceGuidsEx(TRACE_QUERY_INFO_CLASS.TraceGuidQueryList,
                        SafeHGlobalBuffer.Null, 0, buffer, buffer.Length, out int return_length);
                    if (error == Win32Error.ERROR_INSUFFICIENT_BUFFER)
                    {
                        curr_length = return_length;
                        continue;
                    }

                    error.ToNtException();
                    int count = return_length / 16;

                    Guid[] ret = new Guid[count];
                    buffer.ReadArray(0, ret, 0, count);
                    return ret;
                }
            }
        }

        /// <summary>
        /// Get the list of registered trace providers.
        /// </summary>
        /// <returns>The list of trace providers.</returns>
        public static IEnumerable<EventTraceProvider> GetProviders()
        {
            int retry_count = 10;
            int buffer_length = 1024;
            Dictionary<Guid, EventTraceProvider> providers = new Dictionary<Guid, EventTraceProvider>();
            while (retry_count-- > 0)
            {
                using (var buffer = new SafeStructureInOutBuffer<PROVIDER_ENUMERATION_INFO>(buffer_length, false))
                {
                    Win32Error error = Win32NativeMethods.TdhEnumerateProviders(buffer, ref buffer_length);
                    if (error == Win32Error.ERROR_INSUFFICIENT_BUFFER)
                    {
                        continue;
                    }
                    if (error != Win32Error.SUCCESS)
                    {
                        error.ToNtException();
                    }
                    var result = buffer.Result;
                    var data = buffer.Data;
                    TRACE_PROVIDER_INFO[] infos = new TRACE_PROVIDER_INFO[result.NumberOfProviders];
                    buffer.Data.ReadArray(0, infos, 0, infos.Length);
                    foreach (var info in infos)
                    {
                        if (!providers.ContainsKey(info.ProviderGuid))
                        {
                            providers.Add(info.ProviderGuid,
                                new EventTraceProvider(info.ProviderGuid,
                                buffer.ReadNulTerminatedUnicodeString(info.ProviderNameOffset),
                                info.SchemaSource == 0));
                        }
                    }
                    break;
                }
            }
            foreach (var guid in GetTraceGuids())
            {
                if (!providers.ContainsKey(guid))
                {
                    providers.Add(guid, new EventTraceProvider(guid));
                }
            }
            return providers.Values;
        }
    }
}
