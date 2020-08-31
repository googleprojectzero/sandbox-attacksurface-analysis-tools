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
        /// The list of device interface instances.
        /// </summary>
        public IReadOnlyList<DeviceInterfaceInstance> Instances { get; }

        /// <summary>
        /// The list of all device interface properties.
        /// </summary>
        /// <returns>The device interface properties.</returns>
        public IReadOnlyList<DeviceProperty> GetProperties()
        {
            return _properties.Value.AsReadOnly();
        }

        internal DeviceInterfaceClass(Guid guid, bool all_devices)
        {
            Class = guid;
            Instances = DeviceUtils.GetDeviceInterfaceList(guid, null, all_devices)
                .Select(s => new DeviceInterfaceInstance(s, guid)).ToList().AsReadOnly();
            Name = DeviceUtils.GetDeviceInterfaceName(Class);
            _properties = new Lazy<List<DeviceProperty>>(GetAllProperties);
        }
    }
}
