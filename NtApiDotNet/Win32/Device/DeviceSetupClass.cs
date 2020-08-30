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
    /// Class to represent a device setup class.
    /// </summary>
    public sealed class DeviceSetupClass : IDevicePropertyProvider
    {
        private readonly Lazy<List<DeviceProperty>> _properties;

        private List<DeviceProperty> GetAllProperties()
        {
            return DeviceUtils.GetDeviceProperties(Class, false).ToList();
        }

        /// <summary>
        /// The friendly name of the device.
        /// </summary>
        public string FriendlyName { get; }
        /// <summary>
        /// The name of the device class.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The device class installer Guid.
        /// </summary>
        public Guid Class { get; }
        /// <summary>
        /// The security descriptor for the device (if available).
        /// </summary>
        public SecurityDescriptor SecurityDescriptor { get; }
        /// <summary>
        /// The device type.
        /// </summary>
        public FileDeviceType DeviceType { get; }
        /// <summary>
        /// The device characteristics.
        /// </summary>
        public FileDeviceCharacteristics Characteristics { get; }

        /// <summary>
        /// The list of all device setup properties.
        /// </summary>
        /// <returns>The device setup properties.</returns>
        public IReadOnlyList<DeviceProperty> GetProperties()
        {
            return _properties.Value.AsReadOnly();
        }

        /// <summary>
        /// Get device instances.
        /// </summary>
        /// <param name="all_devices">Return all devices.</param>
        /// <returns>The list of devices instances.</returns>
        public IReadOnlyList<DeviceInstance> GetInstances(bool all_devices)
        {
            return DeviceUtils.GetDeviceInstanceList(Class, all_devices).ToList().AsReadOnly();
        }

        /// <summary>
        /// Get device instances.
        /// </summary>
        /// <returns>The list of devices instances.</returns>
        public IReadOnlyList<DeviceInstance> GetInstances()
        {
            return GetInstances(false);
        }

        internal DeviceSetupClass(Guid class_guid)
        {
            Class = class_guid;
            FriendlyName = DeviceUtils.GetClassString(class_guid, false, DevicePropertyKeys.DEVPKEY_DeviceClass_Name, false).GetResultOrDefault(class_guid.ToString());
            Name = DeviceUtils.GetClassString(class_guid, false, DevicePropertyKeys.DEVPKEY_DeviceClass_ClassName, false).GetResultOrDefault(class_guid.ToString());
            DeviceType = (FileDeviceType)DeviceUtils.GetClassInt(class_guid, false, DevicePropertyKeys.DEVPKEY_DeviceClass_DevType, false).GetResultOrDefault(0);
            Characteristics = (FileDeviceCharacteristics)DeviceUtils.GetClassInt(class_guid, false, DevicePropertyKeys.DEVPKEY_DeviceClass_Characteristics, false).GetResultOrDefault(0);
            SecurityDescriptor = DeviceUtils.GetDeviceSecurityDescriptor(class_guid, false).GetResultOrDefault();
            _properties = new Lazy<List<DeviceProperty>>(GetAllProperties);
        }
    }
}
