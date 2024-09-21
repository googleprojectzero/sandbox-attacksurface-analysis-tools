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

namespace NtCoreLib.Win32.Security.Interop;

internal enum MSV1_0_LOGON_SUBMIT_TYPE
{
    MsV1_0InteractiveLogon = 2,
    MsV1_0Lm20Logon,
    MsV1_0NetworkLogon,
    MsV1_0SubAuthLogon,
    MsV1_0WorkstationUnlockLogon = 7,
    // defined in Windows Server 2008 and up
    MsV1_0S4ULogon = 12,
    MsV1_0VirtualLogon = 82,
    // defined in Windows 8 and up
    MsV1_0NoElevationLogon = 83,
    // defined in Windows 8.1 and up
    MsV1_0LuidLogon = 84,
}
