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
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Device
{
    /// <summary>
    /// Class representing a device entry.
    /// </summary>
    public class DeviceInstance : IDevicePropertyProvider
    {
        private readonly int _devinst;
        private readonly Lazy<List<DeviceProperty>> _properties;
        private readonly Lazy<SecurityDescriptor> _sd;
        private readonly Lazy<ServiceInformation> _service_info;

        private SecurityDescriptor GetSecurityDescriptor()
        {
            return DeviceUtils.GetProperty(_devinst, 
                DevicePropertyKeys.DEVPKEY_Device_Security)?.GetSecurityDescriptor();
        }

        private List<DeviceProperty> GetAllProperties()
        {
            return DeviceUtils.GetDeviceProperties(_devinst).ToList();
        }

        private ServiceInformation GetServiceInformation()
        {
            return ServiceUtils.GetServiceInformation(Service, 
                false).GetResultOrDefault(new ServiceInformation(Service));
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
        /// Get the device INF name.
        /// </summary>
        public string INFName { get; }

        /// <summary>
        /// Get the device INF path.
        /// </summary>
        public string INFPath { get; }

        /// <summary>
        /// Get the device stack.
        /// </summary>
        public IReadOnlyList<string> DeviceStack { get; }

        /// <summary>
        /// Indicates if this is a per-session device. If null then not defined.
        /// </summary>
        public uint? SessionId { get; }

        /// <summary>
        /// Indicates if this instance is present.
        /// </summary>
        public bool IsPresent { get; }

        /// <summary>
        /// Indicates the name of the SCM service for the driver.
        /// </summary>
        public string Service { get; }

        /// <summary>
        /// Get path to the driver.
        /// </summary>
        public string DriverPath => _service_info.Value.BinaryPathName ?? string.Empty;

        /// <summary>
        /// Get driver start type.
        /// </summary>
        public ServiceStartType StartType => _service_info.Value.StartType;

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
            if (string.IsNullOrWhiteSpace(Name))
                Name = InstanceId;
            PDOName = DeviceUtils.GetPropertyString(devinst, DevicePropertyKeys.DEVPKEY_Device_PDOName);
            INFName = DeviceUtils.GetPropertyString(devinst, DevicePropertyKeys.DEVPKEY_Device_DriverInfPath);
            SessionId = DeviceUtils.GetPropertyUInt32(devinst, DevicePropertyKeys.DEVPKEY_Device_SessionId);
            Service = DeviceUtils.GetPropertyString(devinst, DevicePropertyKeys.DEVPKEY_Device_Service);
            if (string.IsNullOrEmpty(INFName))
            {
                INFPath = string.Empty;
            }
            else
            {
                INFPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF", INFName);
            }

            DeviceStack = DeviceUtils.GetPropertyStringList(devinst, DevicePropertyKeys.DEVPKEY_Device_Stack).ToList().AsReadOnly();
            Class = DeviceUtils.GetPropertyGuid(devinst, DevicePropertyKeys.DEVPKEY_Device_ClassGuid);
            IsPresent = DeviceUtils.GetPropertyBoolean(devinst, DevicePropertyKeys.DEVPKEY_Device_IsPresent);
            _sd = new Lazy<SecurityDescriptor>(GetSecurityDescriptor);
            _properties = new Lazy<List<DeviceProperty>>(GetAllProperties);
            _service_info = new Lazy<ServiceInformation>(GetServiceInformation);
        }
    }
}
