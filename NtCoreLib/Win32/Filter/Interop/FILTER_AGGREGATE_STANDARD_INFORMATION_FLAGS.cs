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

namespace NtCoreLib.Win32.Filter.Interop;

internal enum FILTER_AGGREGATE_STANDARD_INFORMATION_FLAGS
{
    FLTFL_ASI_IS_MINIFILTER = 0x00000001,
    FLTFL_ASI_IS_LEGACYFILTER = 0x00000002
}
