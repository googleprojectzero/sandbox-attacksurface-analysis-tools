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
    /// Class to access event tracing methods.
    /// </summary>
    public static class EventTracing
    {
        /// <summary>
        /// The default security GUID.
        /// </summary>
        public static readonly Guid DefaultTraceSecurityGuid = new Guid("0811c1af-7a07-4a06-82ed-869455cdf713");

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
            if (error == Win32Error.ERROR_FILE_NOT_FOUND && guid != DefaultTraceSecurityGuid)
            {
                return QueryTraceSecurity(DefaultTraceSecurityGuid, throw_on_error);
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
                return SecurityDescriptor.Parse(buffer, throw_on_error);
            }
        }

        /// <summary>
        /// Register an event trace with a specific GUID.
        /// </summary>
        /// <param name="guid">The event trace GUID.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The event trace.</returns>
        public static NtResult<EventTrace> Register(Guid guid, bool throw_on_error)
        {
            return Win32NativeMethods.EventRegister(ref guid, null, IntPtr.Zero, out SafeEventRegHandle handle)
                .MapDosErrorToStatus().CreateResult(throw_on_error, () => new EventTrace(handle));
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
    }
}
