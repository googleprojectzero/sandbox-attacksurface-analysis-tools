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

using NtCoreLib.Kernel.Interop;
using NtCoreLib.Native.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NtCoreLib.Win32.Device.Interop;

internal static class NativeMethods
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
      out DevicePropertyType PropertyType,
      SafeBuffer PropertyBuffer,
      ref int PropertyBufferSize,
      CmClassType ulFlags
    );

    [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
    internal static extern CrError CM_Get_Class_PropertyW(
      in Guid ClassGUID,
      in DEVPROPKEY PropertyKey,
      out DevicePropertyType PropertyType,
      out int PropertyBuffer,
      ref int PropertyBufferSize,
      CmClassType ulFlags
    );

    [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
    internal static extern CrError CM_Get_Class_PropertyW(
      in Guid ClassGUID,
      in DEVPROPKEY PropertyKey,
      out DevicePropertyType PropertyType,
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
      out DevicePropertyType PropertyType,
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
      out DevicePropertyType PropertyType,
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
