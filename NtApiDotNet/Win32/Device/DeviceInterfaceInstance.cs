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
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Device
{
    /// <summary>
    /// Class to represent a device interface instance.
    /// </summary>
    public sealed class DeviceInterfaceInstance : IDevicePropertyProvider
    {
        private readonly Lazy<string> _device_path;
        private readonly Lazy<List<DeviceProperty>> _properties;

        private List<DeviceProperty> GetAllProperties()
        {
            return DeviceUtils.GetInterfaceInstanceProperties(SymbolicLinkPath).ToList();
        }

        /// <summary>
        /// The instance path to the device.
        /// </summary>
        public string SymbolicLinkPath { get; }
        /// <summary>
        /// The raw device path.
        /// </summary>
        public string DevicePath => _device_path.Value;
        /// <summary>
        /// The device interface class GUID.
        /// </summary>
        public Guid Class { get; }
        /// <summary>
        /// The device instance ID for the device node.
        /// </summary>
        public string InstanceId { get; }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The Win32Path.</returns>
        public override string ToString()
        {
            return SymbolicLinkPath;
        }

        internal DeviceInterfaceInstance(string link_path, Guid class_guid)
        {
            SymbolicLinkPath = link_path;
            Class = class_guid;
            InstanceId = DeviceUtils.GetProperty(link_path, 
                DevicePropertyKeys.DEVPKEY_Device_InstanceId).GetString();
            _device_path = new Lazy<string>(MapWin32ToDevicePath);
            _properties = new Lazy<List<DeviceProperty>>(GetAllProperties);
        }

        internal DeviceInterfaceInstance(string link_path) 
            : this(link_path, GetDeviceInterfaceClass(link_path))
        {
        }

        private static Guid GetDeviceInterfaceClass(string link_path)
        {
            return DeviceUtils.GetProperty(link_path, 
                DevicePropertyKeys.DEVPKEY_DeviceInterface_ClassGuid).GetGuid() 
                ?? throw new ArgumentException("Unknown device interface instance.");
        }

        private string MapWin32ToDevicePath()
        {
            string path = NtFileUtils.DosFileNameToNt(SymbolicLinkPath);
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

        /// <summary>
        /// The list of all device interface instance properties.
        /// </summary>
        /// <returns>The device interface instance properties.</returns>
        public IReadOnlyList<DeviceProperty> GetProperties()
        {
            return _properties.Value.AsReadOnly();
        }
    }
}
