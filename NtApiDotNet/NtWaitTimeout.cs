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

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent an NT timeout
    /// </summary>
    public sealed class NtWaitTimeout
    {
        const long units_per_ms = 10000;

        internal NtWaitTimeout()
        {
        }

        internal NtWaitTimeout(long value)
        {
            Timeout = new LargeInteger(value);
        }

        /// <summary>
        /// Get a timeout which will wait indefinitely.
        /// </summary>
        public static NtWaitTimeout Infinite => new NtWaitTimeout();

        /// <summary>
        /// Get a relative timeout in seconds.
        /// </summary>
        /// <param name="seconds">The number of seconds to wait.</param>
        /// <returns>An instance of the timeout class.</returns>
        public static NtWaitTimeout FromSeconds(int seconds)
        {
            return FromMilliseconds(seconds * 1000L);
        }

        /// <summary>
        /// Get a relative timeout in milliseconds.
        /// </summary>
        /// <param name="ms">The number of milliseconds to wait.</param>
        /// <returns>An instance of the timeout class.</returns>
        public static NtWaitTimeout FromMilliseconds(long ms)
        {
            return new NtWaitTimeout(-(ms * units_per_ms));
        }

        /// <summary>
        /// Get an absolute time out from system start.
        /// </summary>
        /// <param name="absolute">The absolute time to wait until.</param>
        /// <returns>An instance of the timeout class.</returns>
        public static NtWaitTimeout FromAbsolute(long absolute)
        {
            return new NtWaitTimeout(absolute);
        }

        /// <summary>
        /// Get a relative time out from the current time.
        /// </summary>
        /// <param name="relative">The relative time to wait in units of 100ns.</param>
        /// <returns>An instance of the timeout class.</returns>
        public static NtWaitTimeout FromRelative(long relative)
        {
            return new NtWaitTimeout(-relative);
        }

        /// <summary>
        /// Create an absolute wait timeout from a datetime.
        /// </summary>
        /// <param name="date_time">The time for the timeout to complete.</param>
        /// <returns>An instance of the timeout class.</returns>
        public static NtWaitTimeout FromDateTime(DateTime date_time)
        {
            return new NtWaitTimeout(date_time.ToFileTime());
        }

        /// <summary>
        /// The timeout as a long.
        /// </summary>
        public LargeInteger Timeout { get; }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The timeout as a string.</returns>
        public override string ToString()
        {
            if (Timeout == null)
            {
                return "Infinite";
            }

            if (Timeout.QuadPart <= 0)
            {
                return $"Relative: {-Timeout.QuadPart}";
            }
            return $"Absolute: {Timeout.QuadPart}";
        }
    }
}
