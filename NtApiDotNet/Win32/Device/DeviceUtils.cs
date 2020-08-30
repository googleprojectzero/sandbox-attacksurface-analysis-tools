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
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32.Device
{
    /// <summary>
    /// Utilities for interacting with Device, Configuration and Setup APIs.
    /// </summary>
    public static class DeviceUtils
    {
        #region Public Methods
        /// <summary>
        /// Get a list of device interfaces from an Inteface GUID.
        /// </summary>
        /// <param name="interface_class_guid">The interface class GUID for the device.</param>
        /// <param name="device_id">Optional device ID.</param>
        /// <param name="all_devices">True to get all devices, otherwise just present devices.</param>
        /// <returns>List of device interfaces.</returns>
        public static IEnumerable<string> GetDeviceInterfaceList(Guid interface_class_guid, string device_id, bool all_devices)
        {
            CmGetDeviceInterfaceListFlags flags = all_devices ? CmGetDeviceInterfaceListFlags.AllDevices : CmGetDeviceInterfaceListFlags.Present;
            while (true)
            {
                var result = DeviceNativeMethods.CM_Get_Device_Interface_List_Size(out int length, ref interface_class_guid, device_id, flags);
                if (result != CrError.SUCCESS)
                {
                    throw new ArgumentException($"Couldn't get device interface list size. Error: {result}");
                }

                char[] buffer = new char[length];
                result = DeviceNativeMethods.CM_Get_Device_Interface_List(ref interface_class_guid, device_id, buffer, buffer.Length, flags);
                if (result == CrError.SUCCESS)
                {
                    return new string(buffer).Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
                }

                if (result != CrError.BUFFER_SMALL)
                {
                    throw new ArgumentException($"Couldn't get device interface list. Error: {result}");
                }
            }
        }

        /// <summary>
        /// Get a list of present device interfaces from an Inteface GUID.
        /// </summary>
        /// <param name="interface_class_guid">The interface class GUID for the device.</param>
        /// <returns>List of device interfaces.</returns>
        public static IEnumerable<string> GetDeviceInterfaceList(Guid interface_class_guid)
        {
            return GetDeviceInterfaceList(interface_class_guid, null, false);
        }

        /// <summary>
        /// Enumerate installer class GUIDs.
        /// </summary>
        /// <returns>The list of installer class GUIDs.</returns>
        public static IEnumerable<Guid> EnumerateInstallerClasses()
        {
            return EnumerateClasses(CmClassType.Installer);
        }

        /// <summary>
        /// Enumerate interface class GUIDs.
        /// </summary>
        /// <returns>The list of interface class GUIDs.</returns>
        public static IEnumerable<Guid> EnumerateInterfaceClasses()
        {
            return EnumerateClasses(CmClassType.Interface);
        }

        /// <summary>
        /// Query the security descriptor for a device.
        /// </summary>
        /// <param name="installer_class">The installer device class.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor.</returns>
        public static NtResult<SecurityDescriptor> GetDeviceSecurityDescriptor(Guid installer_class, bool throw_on_error)
        {
            using (var buffer = GetDeviceRegistryPropertyBuffer(installer_class, CmDeviceProperty.SECURITY, throw_on_error))
            {
                return buffer.Map(b => new SecurityDescriptor(b.ToArray(), NtType.GetTypeByType<NtFile>()));
            }
        }

        /// <summary>
        /// Query the security descriptor for a device.
        /// </summary>
        /// <param name="installer_class">The installer device class.</param>
        /// <returns>The security descriptor.</returns>
        public static SecurityDescriptor GetDeviceSecurityDescriptor(Guid installer_class)
        {
            return GetDeviceSecurityDescriptor(installer_class, true).Result;
        }

        /// <summary>
        /// Get list of registered device classes.
        /// </summary>
        /// <returns>The list of device classes.</returns>
        public static IReadOnlyList<DeviceSetupClass> GetDeviceSetupClasses()
        {
            //return EnumerateInstallerClasses().Select(c => new DeviceSetupClass(c)).ToList().AsReadOnly();
            return EnumerateInstallerClasses().Select(GetDeviceSetupClass).ToList().AsReadOnly();
        }

        /// <summary>
        /// Get a device class by GUID.
        /// </summary>
        /// <param name="class_guid">The class GUID.</param>
        /// <returns>The device class.</returns>
        public static DeviceSetupClass GetDeviceSetupClass(Guid class_guid)
        {
            if (!ClassExists(class_guid, true))
            {
                throw new ArgumentException("Unknown device setup class.");
            }
            return new DeviceSetupClass(class_guid);
        }

        /// <summary>
        /// Get list of registered device interfaces.
        /// </summary>
        /// <returns>The list of device interfaces.</returns>
        public static IReadOnlyList<DeviceInterfaceClass> GetDeviceInterfaceClasses()
        {
            return EnumerateInterfaceClasses().Select(c => new DeviceInterfaceClass(c)).ToList().AsReadOnly();
        }

        /// <summary>
        /// Get list of device entries.
        /// </summary>
        /// <param name="present">Only return present devices.</param>
        /// <returns>The list of device entries.</returns>
        public static IEnumerable<DeviceInstance> GetDeviceList(bool present)
        {
            DiGetClassFlags flags = DiGetClassFlags.ALLCLASSES;
            if (present)
                flags |= DiGetClassFlags.PRESENT;
            return GetDeviceList(null, null, flags);
        }

        /// <summary>
        /// Get list of present device entries.
        /// </summary>
        /// <returns>The list of device entries.</returns>
        public static IEnumerable<DeviceInstance> GetDeviceList()
        {
            return GetDeviceList(true);
        }

        /// <summary>
        /// Get list of device entries.
        /// </summary>
        /// <param name="class_guid">Specify the Device Setup Class GUID.</param>
        /// <param name="present">Only return present devices.</param>
        /// <returns>The list of device entries.</returns>
        public static IEnumerable<DeviceInstance> GetDeviceList(Guid class_guid, bool present)
        {
            DiGetClassFlags flags = present ? DiGetClassFlags.PRESENT : 0;
            return GetDeviceList(class_guid, null, flags);
        }

        /// <summary>
        /// Get list of present device entries.
        /// </summary>
        /// <param name="class_guid">Specify the Device Setup Class GUID.</param>
        /// <returns>The list of device entries.</returns>
        public static IEnumerable<DeviceInstance> GetDeviceList(Guid class_guid)
        {
            return GetDeviceList(class_guid, true);
        }

        /// <summary>
        /// Get device tree.
        /// </summary>
        /// <returns>The device tree's root node.</returns>
        public static DeviceNode GetDeviceTree()
        {
            DeviceNativeMethods.CM_Locate_DevNodeW(out int root, null, 0).ToNtStatus().ToNtException();
            Dictionary<int, DeviceNode> nodes = new Dictionary<int, DeviceNode>();
            return BuildDeviceTreeNode(root, nodes).First();
        }

        /// <summary>
        /// Get the security descriptor from a device ID.
        /// </summary>
        /// <param name="device_id">The device ID, e.g. ROOT\0</param>
        /// <returns>The security descriptor, null if it can't be found.</returns>
        public static SecurityDescriptor GetDeviceSecurityDescriptor(string device_id)
        {
            if (DeviceNativeMethods.CM_Locate_DevNodeW(out int devinst, device_id, 0) != CrError.SUCCESS)
            {
                return null;
            }
            var prop = GetProperty(devinst, DevicePropertyKeys.DEVPKEY_Device_Security);
            if (prop.Type != DEVPROPTYPE.SECURITY_DESCRIPTOR)
                return null;
            return SecurityDescriptor.Parse(prop.Data, NtType.GetTypeByType<NtFile>(), false).GetResultOrDefault();
        }

        #endregion

        #region Internal Members

        internal static DeviceProperty[] GetDeviceProperties(string instance_id)
        {
            DeviceNativeMethods.CM_Locate_DevNodeW(out int dev_inst, instance_id, 0).ToNtStatus().ToNtException();
            return GetDeviceProperties(dev_inst);
        }

        internal static DeviceProperty[] GetDeviceProperties(int dev_inst)
        {
            int count = 0;
            DeviceProperty[] props = new DeviceProperty[0];
            DeviceNativeMethods.CM_Get_DevNode_Property_Keys(dev_inst, null, ref count, 0);
            if (count == 0)
            {
                return new DeviceProperty[0];
            }

            DEVPROPKEY[] keys = new DEVPROPKEY[count];

            if (DeviceNativeMethods.CM_Get_DevNode_Property_Keys(dev_inst, keys, ref count, 0) != CrError.SUCCESS)
            {
                return new DeviceProperty[0];
            }

            return keys.Take(count).Select(k => GetProperty(dev_inst, k)).ToArray();
        }

        internal static IEnumerable<string> GetDeviceIdList(string filter, CmGetIdListFlags flags)
        {
            int retry_count = 10;
            while (retry_count-- > 0)
            {
                DeviceNativeMethods.CM_Get_Device_ID_List_SizeW(out int length, filter, flags).ToNtStatus().ToNtException();
                using (var buffer = new SafeHGlobalBuffer(length * 2))
                {
                    var result = DeviceNativeMethods.CM_Get_Device_ID_ListW(filter, buffer, length, flags);
                    if (result == CrError.BUFFER_SMALL)
                        continue;
                    result.ToNtStatus().ToNtException();
                    return buffer.ReadUnicodeString(length).Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
                }
            }
            throw new ArgumentException("Couldn't enumerate device ID list.");
        }

        internal static IEnumerable<string> EnumerateEnumerators()
        {
            List<string> ret = new List<string>();
            StringBuilder builder = new StringBuilder(DeviceNativeMethods.MAX_DEVICE_ID_LEN);
            int index = 0;
            int length = DeviceNativeMethods.MAX_DEVICE_ID_LEN;
            CrError result = DeviceNativeMethods.CM_Enumerate_EnumeratorsW(index++, builder, ref length, 0);
            while (result != CrError.NO_SUCH_VALUE)
            {
                if (result != CrError.SUCCESS)
                    break;
                builder.Length = length;
                ret.Add(builder.ToString().Trim('\0'));
                length = DeviceNativeMethods.MAX_DEVICE_ID_LEN;
                result = DeviceNativeMethods.CM_Enumerate_EnumeratorsW(index++, builder, ref length, 0);
            }
            return ret;
        }

        internal static NtResult<string> GetClassString(Guid class_guid, bool interface_guid, DEVPROPKEY key, bool throw_on_error)
        {
            using (var buffer = GetClassProperty(class_guid, interface_guid ? CmClassType.Interface : CmClassType.Installer,
                    key, out DEVPROPTYPE type, throw_on_error))
            {
                if (!buffer.IsSuccess)
                    return buffer.Cast<string>();
                if (type != DEVPROPTYPE.STRING)
                    return NtStatus.STATUS_BAD_KEY.CreateResultFromError<string>(throw_on_error);
                return buffer.Map(b => b.ReadNulTerminatedUnicodeString());
            }
        }

        internal static NtResult<int> GetClassInt(Guid class_guid, bool interface_guid, DEVPROPKEY key, bool throw_on_error)
        {
            int length = 4;
            var result = DeviceNativeMethods.CM_Get_Class_PropertyW(class_guid, key, out DEVPROPTYPE type, out int value, ref length,
                interface_guid ? CmClassType.Interface : CmClassType.Installer).ToNtStatus();
            if (!result.IsSuccess())
                return result.CreateResultFromError<int>(throw_on_error);
            if (type != DEVPROPTYPE.UINT32)
                return NtStatus.STATUS_BAD_KEY.CreateResultFromError<int>(throw_on_error);
            return value.CreateResult();
        }

        internal static NtResult<Guid> GetClassGuid(Guid class_guid, bool interface_guid, DEVPROPKEY key, bool throw_on_error)
        {
            int length = 16;
            var result = DeviceNativeMethods.CM_Get_Class_PropertyW(class_guid, key, out DEVPROPTYPE type, out Guid value, ref length,
                interface_guid ? CmClassType.Interface : CmClassType.Installer).ToNtStatus();
            if (!result.IsSuccess())
                return result.CreateResultFromError<Guid>(throw_on_error);
            if (type != DEVPROPTYPE.GUID)
                return NtStatus.STATUS_BAD_KEY.CreateResultFromError<Guid>(throw_on_error);
            return value.CreateResult();
        }

        internal static DEVPROPKEY[] GetDeviceKeys(Guid class_guid, bool interface_guid)
        {
            DEVPROPKEY[] keys = new DEVPROPKEY[1000];
            int length = 100;
            DeviceNativeMethods.CM_Get_Class_Property_Keys(class_guid,
                keys, ref length, interface_guid ? CmClassType.Interface : CmClassType.Installer).ToNtStatus().ToNtException();
            Array.Resize(ref keys, length);
            return keys;
        }

        internal static string GetDeviceNodeId(int devinst)
        {
            if (DeviceNativeMethods.CM_Get_Device_ID_Size(out int length, devinst, 0) != CrError.SUCCESS)
                return string.Empty;
            StringBuilder builder = new StringBuilder(length);
            if (DeviceNativeMethods.CM_Get_Device_IDW(devinst, builder, length, 0) != CrError.SUCCESS)
                return string.Empty;
            builder.Length = length;
            return builder.ToString();
        }

        internal static NtResult<NtKey> OpenClassKey(Guid class_guid, bool installer, KeyAccessRights desired_access, CmRegDisposition disposition, bool throw_on_error)
        {
            return DeviceNativeMethods.CM_Open_Class_KeyW(class_guid, null, desired_access, disposition,
                out SafeKernelObjectHandle handle,
                installer ? CmClassType.Installer : CmClassType.Interface).ToNtStatus().CreateResult(throw_on_error, () => NtKey.FromHandle(handle));
        }

        internal static bool ClassExists(Guid class_guid, bool installer)
        {
            using (var key = OpenClassKey(class_guid, installer, KeyAccessRights.MaximumAllowed, 
                CmRegDisposition.OpenExisting, false))
            {
                return key.IsSuccess;
            }
        }

        internal static DeviceProperty GetProperty(int devinst, DEVPROPKEY key)
        {
            DeviceProperty ret = new DeviceProperty() { Name = DevicePropertyKeys.KeyToName(key), FmtId = key.fmtid, Pid = key.pid, Data = new byte[0] };
            using (var buffer = new SafeHGlobalBuffer(2000))
            {
                int length = buffer.Length;
                if (DeviceNativeMethods.CM_Get_DevNode_PropertyW(devinst, key, out DEVPROPTYPE type, buffer, ref length, 0) == CrError.SUCCESS)
                {
                    ret.Type = type;
                    ret.Data = buffer.ReadBytes(length);
                }
            }
            return ret;
        }

        internal static string GetPropertyString(int devinst, DEVPROPKEY key)
        {
            return GetProperty(devinst, key)?.GetString();
        }

        internal static string GetDeviceInfPath(int devinst)
        {
            string path = GetPropertyString(devinst, DevicePropertyKeys.DEVPKEY_Device_DriverInfPath);
            if (string.IsNullOrEmpty(path))
                return string.Empty;
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF", path);
        }

        internal static string GetDeviceName(int devinst)
        {
            DeviceProperty prop = GetProperty(devinst, DevicePropertyKeys.DEVPKEY_Device_FriendlyName);
            if (prop?.Type == DEVPROPTYPE.STRING)
                return prop.GetString();
            prop = GetProperty(devinst, DevicePropertyKeys.DEVPKEY_NAME);
            if (prop?.Type == DEVPROPTYPE.STRING)
                return prop.GetString();
            return GetProperty(devinst, DevicePropertyKeys.DEVPKEY_Device_DeviceDesc)?.GetString() ?? string.Empty;
        }

        #endregion

        #region Private Members

        private static NtStatus ToNtStatus(this CrError error)
        {
            return DeviceNativeMethods.CM_MapCrToWin32Err(error, Win32Error.ERROR_INVALID_PARAMETER).MapDosErrorToStatus();
        }

        private static IEnumerable<DeviceInstance> GetDeviceList(OptionalGuid class_guid, string enumerator, DiGetClassFlags flags)
        {
            var devices = new List<DeviceInstance>();

            using (var p = DeviceNativeMethods.SetupDiGetClassDevsW(class_guid, enumerator, IntPtr.Zero, flags))
            {
                if (p.IsInvalid)
                    Win32Utils.GetLastWin32Error().ToNtException();
                int index = 0;
                int size = Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
                SP_DEVINFO_DATA dev_info = new SP_DEVINFO_DATA() { cbSize = size };
                while (DeviceNativeMethods.SetupDiEnumDeviceInfo(p, index++, ref dev_info))
                {
                    devices.Add(new DeviceInstance(dev_info.DevInst));
                    dev_info.cbSize = size;
                }

                return devices.AsReadOnly();
            }
        }

        private static IEnumerable<Guid> EnumerateClasses(CmClassType flags)
        {
            Guid guid = Guid.Empty;
            int index = 0;
            while (true)
            {
                var result = DeviceNativeMethods.CM_Enumerate_Classes(index++, ref guid, flags);
                if (result == CrError.NO_SUCH_VALUE)
                {
                    break;
                }

                if (result == CrError.INVALID_DATA)
                {
                    continue;
                }

                if (result != CrError.SUCCESS)
                {
                    throw new ArgumentException($"Failed to enumerate device class. Error: {result}");
                }

                yield return guid;
            }
        }

        private static NtResult<SafeHGlobalBuffer> GetDeviceRegistryPropertyBuffer(Guid class_guid, CmDeviceProperty property, bool throw_on_error)
        {
            int length = 0;
            var result = DeviceNativeMethods.CM_Get_Class_Registry_PropertyW(class_guid, property, out RegistryValueType reg_type,
                SafeHGlobalBuffer.Null, ref length, 0, IntPtr.Zero);

            if (result != CrError.BUFFER_SMALL)
            {
                return result.ToNtStatus().CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
            }

            using (var buffer = new SafeHGlobalBuffer(length))
            {
                return DeviceNativeMethods.CM_Get_Class_Registry_PropertyW(class_guid, property, out reg_type,
                    buffer, ref length, 0, IntPtr.Zero).ToNtStatus().CreateResult(throw_on_error, () => buffer.Detach());
            }
        }

        private static NtResult<SafeHGlobalBuffer> GetClassProperty(Guid class_guid, CmClassType flags, DEVPROPKEY key, out DEVPROPTYPE type, bool throw_on_error)
        {
            int length = 0;
            var result = DeviceNativeMethods.CM_Get_Class_PropertyW(class_guid, key, out type, SafeHGlobalBuffer.Null, ref length, flags);
            if (result != CrError.BUFFER_SMALL)
            {
                return result.ToNtStatus().CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
            }

            using (var buffer = new SafeHGlobalBuffer(length))
            {
                return DeviceNativeMethods.CM_Get_Class_PropertyW(class_guid, key, out type, buffer, 
                    ref length, flags).ToNtStatus().CreateResult(throw_on_error, () => buffer.Detach());
            }
        }

        private static IEnumerable<DeviceNode> BuildDeviceTreeNode(int node, Dictionary<int, DeviceNode> dict)
        {
            List<DeviceNode> nodes = new List<DeviceNode>();
            while (node != 0)
            {
                DeviceNode curr_node = new DeviceNode(node);
                dict[node] = curr_node;
                nodes.Add(curr_node);
                if (DeviceNativeMethods.CM_Get_Child(out int child, node, 0) == CrError.SUCCESS)
                {
                    curr_node.AddRange(BuildDeviceTreeNode(child, dict));
                }
                if (DeviceNativeMethods.CM_Get_Sibling(out node, node, 0) != CrError.SUCCESS)
                    break;
            }
            return nodes;
        }

        #endregion
    }
}
