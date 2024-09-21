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

namespace NtCoreLib.Win32.Device.Interop;

[Flags]
internal enum CmGetIdListFlags
{
    CM_GETIDLIST_FILTER_NONE = 0x00000000,
    CM_GETIDLIST_FILTER_ENUMERATOR = 0x00000001,
    CM_GETIDLIST_FILTER_SERVICE = 0x00000002,
    CM_GETIDLIST_FILTER_EJECTRELATIONS = 0x00000004,
    CM_GETIDLIST_FILTER_REMOVALRELATIONS = 0x00000008,
    CM_GETIDLIST_FILTER_POWERRELATIONS = 0x00000010,
    CM_GETIDLIST_FILTER_BUSRELATIONS = 0x00000020,
    CM_GETIDLIST_DONOTGENERATE = 0x10000040,
    CM_GETIDLIST_FILTER_TRANSPORTRELATIONS = 0x00000080,
    CM_GETIDLIST_FILTER_PRESENT = 0x00000100,
    CM_GETIDLIST_FILTER_CLASS = 0x00000200,
}
