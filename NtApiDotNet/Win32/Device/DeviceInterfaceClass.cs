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

namespace NtApiDotNet.Win32.Device
{
    /// <summary>
    /// Class to represent a device interface.
    /// </summary>
    public sealed class DeviceInterfaceClass : IDevicePropertyProvider
    {
        private readonly Lazy<List<DeviceProperty>> _properties;

        private List<DeviceProperty> GetAllProperties()
        {
            return DeviceUtils.GetDeviceProperties(Class, true).ToList();
        }

        /// <summary>
        /// The name of the interface class.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The device interface GUID.
        /// </summary>
        public Guid Class { get; }
        /// <summary>
        /// The list of win32 paths to open the device.
        /// </summary>
        public IReadOnlyList<string> Win32Paths { get; }
        /// <summary>
        /// The list of devices.
        /// </summary>
        public IReadOnlyList<string> DevicePaths { get; }

        /// <summary>
        /// The list of all device interface properties.
        /// </summary>
        /// <returns>The device interface properties.</returns>
        public IReadOnlyList<DeviceProperty> GetProperties()
        {
            return _properties.Value.AsReadOnly();
        }

        internal DeviceInterfaceClass(Guid guid)
        {
            Class = guid;
            Win32Paths = DeviceUtils.GetDeviceInterfaceList(guid).ToList().AsReadOnly();
            DevicePaths = Win32Paths.Select(MapWin32ToDevicePath).ToList().AsReadOnly();
            Name = DeviceUtils.GetDeviceInterfaceName(Class) ?? string.Empty;
            _properties = new Lazy<List<DeviceProperty>>(GetAllProperties);
        }

        private static string MapWin32ToDevicePath(string path)
        {
            path = NtFileUtils.DosFileNameToNt(path);
            string final_component = string.Empty;
            // Strip off any remaining path.
            if (path.StartsWith(@"\??\"))
            {
                int slash_index = path.IndexOf('\\', 4);
                if (slash_index >= 0)
                {
                    final_component = path.Substring(slash_index);
                    path = path.Substring(0, slash_index);
                }
            }

            using (var link = NtSymbolicLink.Open(path, null, SymbolicLinkAccessRights.Query, false))
            {
                if (link.IsSuccess)
                {
                    path = link.Result.Target;
                }
            }

            return path + final_component;
        }
    }
}
