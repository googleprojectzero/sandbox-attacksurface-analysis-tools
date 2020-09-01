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
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32.Device
{
    internal enum CmGetDeviceInterfaceListFlags
    {
        Present = 0,
        AllDevices = 1,
    }

    internal enum CrError
    {
        SUCCESS = 0x00000000,
        DEFAULT = 0x00000001,
        OUT_OF_MEMORY = 0x00000002,
        INVALID_POINTER = 0x00000003,
        INVALID_FLAG = 0x00000004,
        INVALID_DEVNODE = 0x00000005,
        INVALID_RES_DES = 0x00000006,
        INVALID_LOG_CONF = 0x00000007,
        INVALID_ARBITRATOR = 0x00000008,
        INVALID_NODELIST = 0x00000009,
        DEVNODE_HAS_REQS = 0x0000000A,
        INVALID_RESOURCEID = 0x0000000B,
        DLVXD_NOT_FOUND = 0x0000000C,
        NO_SUCH_DEVNODE = 0x0000000D,
        NO_MORE_LOG_CONF = 0x0000000E,
        NO_MORE_RES_DES = 0x0000000F,
        ALREADY_SUCH_DEVNODE = 0x00000010,
        INVALID_RANGE_LIST = 0x00000011,
        INVALID_RANGE = 0x00000012,
        FAILURE = 0x00000013,
        NO_SUCH_LOGICAL_DEV = 0x00000014,
        CREATE_BLOCKED = 0x00000015,
        NOT_SYSTEM_VM = 0x00000016,
        REMOVE_VETOED = 0x00000017,
        APM_VETOED = 0x00000018,
        INVALID_LOAD_TYPE = 0x00000019,
        BUFFER_SMALL = 0x0000001A,
        NO_ARBITRATOR = 0x0000001B,
        NO_REGISTRY_HANDLE = 0x0000001C,
        REGISTRY_ERROR = 0x0000001D,
        INVALID_DEVICE_ID = 0x0000001E,
        INVALID_DATA = 0x0000001F,
        INVALID_API = 0x00000020,
        DEVLOADER_NOT_READY = 0x00000021,
        NEED_RESTART = 0x00000022,
        NO_MORE_HW_PROFILES = 0x00000023,
        DEVICE_NOT_THERE = 0x00000024,
        NO_SUCH_VALUE = 0x00000025,
        WRONG_TYPE = 0x00000026,
        INVALID_PRIORITY = 0x00000027,
        NOT_DISABLEABLE = 0x00000028,
        FREE_RESOURCES = 0x00000029,
        QUERY_VETOED = 0x0000002A,
        CANT_SHARE_IRQ = 0x0000002B,
        NO_DEPENDENT = 0x0000002C,
        SAME_RESOURCES = 0x0000002D,
        NO_SUCH_REGISTRY_KEY = 0x0000002E,
        INVALID_MACHINENAME = 0x0000002F,
        REMOTE_COMM_FAILURE = 0x00000030,
        MACHINE_UNAVAILABLE = 0x00000031,
        NO_CM_SERVICES = 0x00000032,
        ACCESS_DENIED = 0x00000033,
        CALL_NOT_IMPLEMENTED = 0x00000034,
        INVALID_PROPERTY = 0x00000035,
        DEVICE_INTERFACE_ACTIVE = 0x00000036,
        NO_SUCH_DEVICE_INTERFACE = 0x00000037,
        INVALID_REFERENCE_STRING = 0x00000038,
        INVALID_CONFLICT_LIST = 0x00000039,
        INVALID_INDEX = 0x0000003A,
        INVALID_STRUCTURE_SIZE = 0x0000003B,
    }

    internal enum CmClassType
    {
        Installer = 0,
        Interface = 1,
    }

    internal enum CmDeviceProperty
    {
        DEVICEDESC = 0x01,
        HARDWAREID = 0x02,
        COMPATIBLEIDS = 0x03,
        UNUSED0 = 0x04,
        SERVICE = 0x05,
        UNUSED1 = 0x06,
        UNUSED2 = 0x07,
        CLASS = 0x08,
        CLASSGUID = 0x09,
        DRIVER = 0x0A,
        CONFIGFLAGS = 0x0B,
        MFG = 0x0C,
        FRIENDLYNAME = 0x0D,
        LOCATION_INFORMATION = 0x0E,
        PHYSICAL_DEVICE_OBJECT_NAME = 0x0F,
        CAPABILITIES = 0x10,
        UI_NUMBER = 0x11,
        UPPERFILTERS = 0x12,
        LOWERFILTERS = 0x13,
        BUSTYPEGUID = 0x14,
        LEGACYBUSTYPE = 0x15,
        BUSNUMBER = 0x16,
        ENUMERATOR_NAME = 0x17,
        SECURITY = 0x18,
        SECURITY_SDS = 0x19,
        DEVTYPE = 0x1A,
        EXCLUSIVE = 0x1B,
        CHARACTERISTICS = 0x1C,
        ADDRESS = 0x1D,
        UI_NUMBER_DESC_FORMAT = 0x1E,
        DEVICE_POWER_DATA = 0x1F,
        REMOVAL_POLICY = 0x20,
        REMOVAL_POLICY_HW_DEFAULT = 0x21,
        REMOVAL_POLICY_OVERRIDE = 0x22,
        INSTALL_STATE = 0x23,
        LOCATION_PATHS = 0x24,
        BASE_CONTAINERID = 0x25,
    }

    /// <summary>
    /// Device property types.
    /// </summary>
    public enum DEVPROPTYPE
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        EMPTY = 0x00000000, // nothing, no property data
        NULL = 0x00000001, // null property data
        SBYTE = 0x00000002, // 8-bit signed int (SBYTE)
        BYTE = 0x00000003, // 8-bit unsigned int (BYTE)
        INT16 = 0x00000004, // 16-bit signed int (SHORT)
        UINT16 = 0x00000005, // 16-bit unsigned int (USHORT)
        INT32 = 0x00000006, // 32-bit signed int (LONG)
        UINT32 = 0x00000007, // 32-bit unsigned int (ULONG)
        INT64 = 0x00000008, // 64-bit signed int (LONG64)
        UINT64 = 0x00000009, // 64-bit unsigned int (ULONG64)
        FLOAT = 0x0000000A, // 32-bit floating-point (FLOAT)
        DOUBLE = 0x0000000B, // 64-bit floating-point (DOUBLE)
        DECIMAL = 0x0000000C, // 128-bit data (DECIMAL)
        GUID = 0x0000000D, // 128-bit unique identifier (GUID)
        CURRENCY = 0x0000000E, // 64 bit signed int currency value (CURRENCY)
        DATE = 0x0000000F, // date (DATE)
        FILETIME = 0x00000010, // file time (FILETIME)
        BOOLEAN = 0x00000011, // 8-bit boolean (DEVPROP_BOOLEAN)
        STRING = 0x00000012, // null-terminated string
        STRING_LIST = (STRING | LIST), // multi-sz string list
        SECURITY_DESCRIPTOR = 0x00000013, // self-relative binary SECURITY_DESCRIPTOR
        SECURITY_DESCRIPTOR_STRING = 0x00000014, // security descriptor string (SDDL format)
        DEVPROPKEY = 0x00000015, // device property key (DEVPROPKEY)
        DEVPROPTYPE = 0x00000016, // device property type (DEVPROPTYPE)
        BINARY   =   (BYTE|ARRAY), // custom binary data
        ERROR = 0x00000017, // 32-bit Win32 system error code
        NTSTATUS = 0x00000018, // 32-bit NTSTATUS code
        STRING_INDIRECT = 0x00000019, // string resource (@[path\]<dllname>,-<strId>)
        ARRAY = 0x00001000,  // array of fixed-sized data elements
        LIST = 0x00002000,  // list of variable-sized data elements
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SP_DEVINFO_DATA
    {
        public int cbSize;
        public Guid ClassGuid;
        public int DevInst;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SP_DEVICE_INTERFACE_DATA
    {
        public int cbSize;
        public Guid InterfaceClassGuid;
        public int Flags;
        public IntPtr Reserved;
    }

    [Flags]
    internal enum DiGetClassFlags
    {
        DEFAULT = 0x00000001,
        PRESENT = 0x00000002,
        ALLCLASSES = 0x00000004,
        PROFILE = 0x00000008,
        DEVICEINTERFACE = 0x00000010,
    }

    internal enum CmRegDisposition
    {
        OpenAlways = 0x00000000,
        OpenExisting = 0x00000001
    }

    [Flags]
    internal enum CmGetIdListFlags
    {
        CM_GETIDLIST_FILTER_NONE                = 0x00000000,
        CM_GETIDLIST_FILTER_ENUMERATOR          = 0x00000001,
        CM_GETIDLIST_FILTER_SERVICE             = 0x00000002,
        CM_GETIDLIST_FILTER_EJECTRELATIONS      = 0x00000004,
        CM_GETIDLIST_FILTER_REMOVALRELATIONS    = 0x00000008,
        CM_GETIDLIST_FILTER_POWERRELATIONS      = 0x00000010,
        CM_GETIDLIST_FILTER_BUSRELATIONS        = 0x00000020,
        CM_GETIDLIST_DONOTGENERATE              = 0x10000040,
        CM_GETIDLIST_FILTER_TRANSPORTRELATIONS  = 0x00000080,
        CM_GETIDLIST_FILTER_PRESENT             = 0x00000100,
        CM_GETIDLIST_FILTER_CLASS               = 0x00000200,
    }

    internal static class DeviceNativeMethods
    {
        internal const int MAX_DEVICE_ID_LEN = 200;

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Device_Interface_List(ref Guid InterfaceClassGuid, string pDeviceID, 
            [Out] char[] Buffer, int BufferLen, CmGetDeviceInterfaceListFlags ulFlags);

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Device_Interface_List_Size(out int pulLen, ref Guid InterfaceClassGuid, 
            string pDeviceID, CmGetDeviceInterfaceListFlags ulFlags);

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Enumerate_Classes(int ulClassIndex, ref Guid ClassGuid, CmClassType ulFlags);

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Class_Registry_PropertyW(
          in Guid ClassGuid,
          CmDeviceProperty ulProperty,
          out RegistryValueType pulRegDataType,
          SafeBuffer Buffer,
          ref int pulLength,
          int ulFlags,
          IntPtr hMachine
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Class_Registry_PropertyW(
          in Guid ClassGuid,
          CmDeviceProperty ulProperty,
          out RegistryValueType pulRegDataType,
          out int Buffer,
          ref int pulLength,
          int ulFlags,
          IntPtr hMachine
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error CM_MapCrToWin32Err(
            CrError CmReturnCode,
            Win32Error DefaultError
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Class_PropertyW(
          in Guid ClassGUID,
          in DEVPROPKEY PropertyKey,
          out DEVPROPTYPE PropertyType,
          SafeBuffer PropertyBuffer,
          ref int PropertyBufferSize,
          CmClassType ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Class_PropertyW(
          in Guid ClassGUID,
          in DEVPROPKEY PropertyKey,
          out DEVPROPTYPE PropertyType,
          out int PropertyBuffer,
          ref int PropertyBufferSize,
          CmClassType ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Class_PropertyW(
          in Guid ClassGUID,
          in DEVPROPKEY PropertyKey,
          out DEVPROPTYPE PropertyType,
          out Guid PropertyBuffer,
          ref int PropertyBufferSize,
          CmClassType ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Class_Property_Keys(
            in Guid ClassGUID,
            [Out] DEVPROPKEY[] PropertyKeyArray,
            ref int PropertyKeyCount,
            CmClassType ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_DevNode_Property_Keys(
            int dnDevInst,
            [Out] DEVPROPKEY[] PropertyKeyArray,
            ref int PropertyKeyCount,
            int ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_DevNode_PropertyW(
          int dnDevInst,
          in DEVPROPKEY PropertyKey,
          out DEVPROPTYPE PropertyType,
          SafeBuffer PropertyBuffer,
          ref int PropertyBufferSize,
          int ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Locate_DevNodeW(
              out int pdnDevInst,
              string pDeviceID,
              int ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Child(
            out int pdnDevInst,
            int dnDevInst,
            int ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Sibling(
            out int pdnDevInst,
            int dnDevInst,
            int ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Device_ID_Size(
          out int pulLen,
          int dnDevInst,
          int ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Device_IDW(
          int dnDevInst,
          [Out] StringBuilder Buffer,
          int BufferLen,
          int ulFlags
        );

        [DllImport("SetupAPI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeDeviceInfoSetHandle SetupDiCreateDeviceInfoList(
          OptionalGuid ClassGuid,
          IntPtr hwndParent
        );

        [DllImport("SetupAPI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetupDiDestroyDeviceInfoList(
            IntPtr DeviceInfoSet
        );

        [DllImport("SetupAPI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetupDiEnumDeviceInfo(
          SafeDeviceInfoSetHandle DeviceInfoSet,
          int MemberIndex,
          ref SP_DEVINFO_DATA DeviceInfoData
        );

        [DllImport("SetupAPI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeDeviceInfoSetHandle SetupDiGetClassDevsW(
          OptionalGuid ClassGuid,
          string Enumerator,
          IntPtr hwndParent,
          DiGetClassFlags Flags
        );

        [DllImport("SetupAPI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetupDiGetDeviceInstanceIdW(
          SafeDeviceInfoSetHandle DeviceInfoSet,
          in SP_DEVINFO_DATA DeviceInfoData,
          [Out] StringBuilder DeviceInstanceId,
          int DeviceInstanceIdSize,
          out int RequiredSize
        );

        [DllImport("SetupAPI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetupDiOpenDeviceInterfaceW(
              SafeDeviceInfoSetHandle DeviceInfoSet,
              string DevicePath,
              int OpenFlags,
              out SP_DEVICE_INTERFACE_DATA DeviceInterfaceData
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Open_Class_KeyW(
          in Guid ClassGuid,
          string pszClassName,
          KeyAccessRights samDesired,
          CmRegDisposition Disposition,
          out SafeKernelObjectHandle phkClass,
          CmClassType ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Enumerate_EnumeratorsW(
          int ulEnumIndex,
          [Out] StringBuilder Buffer,
          ref int pulLength,
          int ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Device_ID_List_SizeW(
            out int pulLen,
            string pszFilter,
            CmGetIdListFlags ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Device_ID_ListW(
          string pszFilter,
          SafeBuffer Buffer,
          int BufferLen,
          CmGetIdListFlags ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Device_Interface_Property_KeysW(
          string pszDeviceInterface,
          [Out] DEVPROPKEY[] PropertyKeyArray,
          ref int PropertyKeyCount,
          int ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Device_Interface_PropertyW(
          string pszDeviceInterface,
          in DEVPROPKEY PropertyKey,
          out DEVPROPTYPE PropertyType,
          SafeBuffer PropertyBuffer,
          ref int PropertyBufferSize,
          int ulFlags
        );

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        internal static extern CrError CM_Get_Parent(
          out int pdnDevInst,
          int dnDevInst,
          int ulFlags
        );

        [DllImport("Propsys.dll", CharSet = CharSet.Unicode)]
        internal static extern int PSGetNameFromPropertyKey(
            in DEVPROPKEY propkey,
            out string ppszCanonicalName
        );
    }
}
