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

namespace NtCoreLib.Win32.Device.Interop;

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
