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
    /// Class representing a device entry.
    /// </summary>
    public class DeviceInstance
    {
        private readonly int _devinst;
        private readonly Lazy<List<DeviceProperty>> _properties;
        private readonly Lazy<SecurityDescriptor> _sd;

        private SecurityDescriptor GetSecurityDescriptor()
        {
            return DeviceUtils.GetProperty(_devinst, 
                DevicePropertyKeys.DEVPKEY_Device_Security)?.GetSecurityDescriptor();
        }

        private List<DeviceProperty> GetAllProperties()
        {
            return DeviceUtils.GetDeviceProperties(_devinst).ToList();
        }

        /// <summary>
        /// The name of the device instance.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The device setup class GUID.
        /// </summary>
        public Guid Class { get; }

        /// <summary>
        /// The device instance ID.
        /// </summary>
        public string InstanceId { get; }

        /// <summary>
        /// Get the device PDO name.
        /// </summary>
        public string PDOName { get; }

        /// <summary>
        /// Get the device INF path.
        /// </summary>
        public string INFPath { get; }

        /// <summary>
        /// Get the device stack.
        /// </summary>
        public IReadOnlyList<string> DeviceStack { get; }

        /// <summary>
        /// The list of all device properties.
        /// </summary>
        /// <returns>The device properties.</returns>
        public IReadOnlyList<DeviceProperty> GetProperties()
        {
            return _properties.Value.AsReadOnly();
        }

        /// <summary>
        /// Get the setup class for this instance.
        /// </summary>
        /// <returns>Returns the setup class.</returns>
        /// <exception cref="ArgumentException">Thrown if invalid setup GUID.</exception>
        public DeviceSetupClass GetSetupClass()
        {
            return DeviceUtils.GetDeviceSetupClass(Class);
        }

        /// <summary>
        /// Optional security descriptor for device node.
        /// </summary>
        public SecurityDescriptor SecurityDescriptor => _sd.Value;

        internal DeviceInstance(int devinst)
        {
            _devinst = devinst;
            InstanceId = DeviceUtils.GetDeviceNodeId(devinst);
            Name = DeviceUtils.GetDeviceName(devinst);
            PDOName = DeviceUtils.GetPropertyString(devinst, DevicePropertyKeys.DEVPKEY_Device_PDOName);
            INFPath = DeviceUtils.GetDeviceInfPath(devinst);
            DeviceStack = DeviceUtils.GetPropertyStringList(devinst, DevicePropertyKeys.DEVPKEY_Device_Stack).ToList().AsReadOnly();
            Class = DeviceUtils.GetPropertyGuid(devinst, DevicePropertyKeys.DEVPKEY_Device_ClassGuid);
            _sd = new Lazy<SecurityDescriptor>(GetSecurityDescriptor);
            _properties = new Lazy<List<DeviceProperty>>(GetAllProperties);
        }
    }
}
