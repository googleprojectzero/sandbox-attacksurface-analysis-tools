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

namespace NtApiDotNet.Win32.Device
{
    /// <summary>
    /// Enumerated type for device stack type.
    /// </summary>
    public enum DeviceStackEntryType
    {
        /// <summary>
        /// Unknown type.
        /// </summary>
        Unknown,
        /// <summary>
        /// Entry is for the function driver.
        /// </summary>
        Function,
        /// <summary>
        /// Entry is for the bus driver.
        /// </summary>
        Bus,
        /// <summary>
        /// Entry is for an upper filter.
        /// </summary>
        UpperFilter,
        /// <summary>
        /// Entry is for the lower filter.
        /// </summary>
        LowerFilter,
        /// <summary>
        /// Entry is for a filter.
        /// </summary>
        Filter
    }

    /// <summary>
    /// Class to represent an entry on the stack.
    /// </summary>
    public class DeviceStackEntry
    {
        /// <summary>
        /// Name of the driver.
        /// </summary>
        public string Driver { get; }
        /// <summary>
        /// Path to the driver.
        /// </summary>
        public string DriverPath { get; }
        /// <summary>
        /// Stack entry type.
        /// </summary>
        public DeviceStackEntryType Type { get; }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The name of the driver in the stack.</returns>
        public override string ToString()
        {
            return Driver;
        }

        internal DeviceStackEntry(string driver, string driver_path, DeviceStackEntryType type)
        {
            Driver = driver;
            DriverPath = driver_path;
            Type = type;
        }
    }
}
