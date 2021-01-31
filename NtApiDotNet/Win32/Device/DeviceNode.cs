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
    /// Class representing a device node.
    /// </summary>
    public class DeviceNode : IDevicePropertyProvider
    {
        private readonly int _devinst;
        private readonly Lazy<List<DeviceProperty>> _properties;
        private readonly Lazy<SecurityDescriptor> _sd;
        private readonly Lazy<ServiceInformation> _service_info;
        private readonly Lazy<IReadOnlyList<DeviceStackEntry>> _device_stack;
        private readonly Lazy<DeviceNode> _parent;

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
            return ServiceUtils.GetServiceInformation(null, Service, 
                false).GetResultOrDefault(new ServiceInformation(null, Service));
        }

        private DeviceNode GetParent()
        {
            if (DeviceNativeMethods.CM_Get_Parent(out int parent, _devinst, 0) != CrError.SUCCESS)
                return null;
            return new DeviceNode(parent);
        }

        private string GetServiceName(string path)
        {
            if (!path.Contains('\\'))
            {
                return path;
            }

            return Path.GetFileName(path);
        }

        private IReadOnlyList<DeviceStackEntry> BuildDeviceStack()
        {
            var setup_class = new DeviceSetupClass(Class);
            var parent = Parent;
            HashSet<string> upper_filters = new HashSet<string>(UpperFilters.Concat(setup_class.UpperFilters), StringComparer.OrdinalIgnoreCase);
            HashSet<string> lower_filters = new HashSet<string>(LowerFilters.Concat(setup_class.LowerFilters), StringComparer.OrdinalIgnoreCase);
            bool found_fdo = false;
            bool found_pdo = false;

            string service_name = GetServiceName(_service_info.Value.ServiceStartName);
            if (string.IsNullOrWhiteSpace(service_name))
            {
                service_name = Service;
            }
            List<DeviceStackEntry> stack = new List<DeviceStackEntry>();
            foreach (var driver_path in DeviceStackPaths)
            {
                DeviceStackEntryType type = DeviceStackEntryType.Unknown;
                string name = GetServiceName(driver_path);

                if (name.Equals(service_name, StringComparison.OrdinalIgnoreCase) && !found_fdo)
                {
                    type = DeviceStackEntryType.Function;
                    found_fdo = true;
                }
                else if (Parent != null && name.Equals(Parent.Service, StringComparison.OrdinalIgnoreCase) && !found_pdo)
                {
                    type = DeviceStackEntryType.Bus;
                    found_pdo = true;
                }
                else if (BusType == DeviceBusTypeGuids.GUID_BUS_TYPE_SW_DEVICE &&
                    !found_pdo &&
                    name.Equals("SoftwareDevice", StringComparison.OrdinalIgnoreCase))
                {
                    type = DeviceStackEntryType.Bus;
                    found_pdo = true;
                }
                else if (name.Equals("PnpManager", StringComparison.OrdinalIgnoreCase))
                {
                    if (Parent == null)
                    {
                        type = DeviceStackEntryType.Function;
                        found_fdo = true;
                    }
                    else
                    {
                        type = DeviceStackEntryType.Bus;
                        found_pdo = true;
                    }
                }
                else if (!found_fdo && upper_filters.Contains(name))
                {
                    type = DeviceStackEntryType.UpperFilter;
                }
                else if (found_fdo && lower_filters.Contains(name))
                {
                    type = DeviceStackEntryType.LowerFilter;
                }
                else
                {
                    type = DeviceStackEntryType.Filter;
                }

                stack.Add(new DeviceStackEntry(name, driver_path, type));
            }

            return stack.AsReadOnly();
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
        public IReadOnlyList<DeviceStackEntry> DeviceStack => _device_stack.Value;

        /// <summary>
        /// The the device stack as a list of driver paths.
        /// </summary>
        public IReadOnlyList<string> DeviceStackPaths { get; }

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
        /// Get the parent device node.
        /// </summary>
        /// <returns>The parent device node. Returns null if reached the root.</returns>
        public virtual DeviceNode Parent => _parent.Value;

        /// <summary>
        /// List of upper filters.
        /// </summary>
        public IReadOnlyList<string> UpperFilters { get; }

        /// <summary>
        /// List of lower filters.
        /// </summary>
        public IReadOnlyList<string> LowerFilters { get; }

        /// <summary>
        /// Container ID.
        /// </summary>
        public Guid ContainerId { get; }

        /// <summary>
        /// Type of bus for the device.
        /// </summary>
        public Guid BusType { get; }

        /// <summary>
        /// Get if the device is a user-mode device.
        /// </summary>
        public bool UserMode => _service_info.Value.ServiceStartName.Equals(@"\Driver\WudfRd", StringComparison.OrdinalIgnoreCase);

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
        /// Get list of parent nodes.
        /// </summary>
        /// <returns>The list of parent nodes.</returns>
        public IReadOnlyList<DeviceNode> GetParentNodes()
        {
            List<DeviceNode> nodes = new List<DeviceNode>();
            var curr_node = Parent;
            while (curr_node != null)
            {
                nodes.Add(curr_node);
                curr_node = curr_node.Parent;
            }
            return nodes.AsReadOnly();
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return InstanceId;
        }

        /// <summary>
        /// Optional security descriptor for device node.
        /// </summary>
        public SecurityDescriptor SecurityDescriptor => _sd.Value;

        /// <summary>
        /// Indicates the device node has a security descriptor.
        /// </summary>
        public bool HasSecurityDescriptor => SecurityDescriptor != null;

        internal DeviceNode(int devinst)
        {
            _devinst = devinst;
            InstanceId = DeviceUtils.GetDeviceNodeId(devinst);
            Name = DeviceUtils.GetDeviceName(devinst);
            if (string.IsNullOrWhiteSpace(Name))
                Name = InstanceId;
            PDOName = DeviceUtils.GetPropertyString(devinst, DevicePropertyKeys.DEVPKEY_Device_PDOName);
            INFName = DeviceUtils.GetPropertyString(devinst, DevicePropertyKeys.DEVPKEY_Device_DriverInfPath);
            SessionId = DeviceUtils.GetPropertyUInt32(devinst, DevicePropertyKeys.DEVPKEY_Device_SessionId);
            Service = GetServiceName(DeviceUtils.GetPropertyString(devinst, DevicePropertyKeys.DEVPKEY_Device_Service));
            if (string.IsNullOrEmpty(INFName))
            {
                INFPath = string.Empty;
            }
            else
            {
                INFPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF", INFName);
            }

            DeviceStackPaths = DeviceUtils.GetPropertyStringList(devinst, DevicePropertyKeys.DEVPKEY_Device_Stack);
            _device_stack = new Lazy<IReadOnlyList<DeviceStackEntry>>(BuildDeviceStack);
            _parent = new Lazy<DeviceNode>(GetParent);
            Class = DeviceUtils.GetPropertyGuid(devinst, DevicePropertyKeys.DEVPKEY_Device_ClassGuid);
            IsPresent = DeviceUtils.GetPropertyBoolean(devinst, DevicePropertyKeys.DEVPKEY_Device_IsPresent);
            UpperFilters = DeviceUtils.GetPropertyStringList(devinst, DevicePropertyKeys.DEVPKEY_Device_UpperFilters);
            LowerFilters = DeviceUtils.GetPropertyStringList(devinst, DevicePropertyKeys.DEVPKEY_Device_LowerFilters);
            ContainerId = DeviceUtils.GetPropertyGuid(devinst, DevicePropertyKeys.DEVPKEY_Device_ContainerId);
            BusType = DeviceUtils.GetPropertyGuid(devinst, DevicePropertyKeys.DEVPKEY_Device_BusTypeGuid);
            _sd = new Lazy<SecurityDescriptor>(GetSecurityDescriptor);
            _properties = new Lazy<List<DeviceProperty>>(GetAllProperties);
            _service_info = new Lazy<ServiceInformation>(GetServiceInformation);
        }
    }
}
