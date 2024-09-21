//  Copyright 2023 Google LLC. All Rights Reserved.
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
//
//  Note this is relicensed from OleViewDotNet by the author.

namespace NtCoreLib.Win32.SideBySide.Interop;

enum ACTIVATION_CONTEXT_SECTION_ID
{
    UNKNOWN = 0,
    ASSEMBLY_INFORMATION = 1,
    DLL_REDIRECTION = 2,
    CLASS_REDIRECTION = 3,
    COM_SERVER_REDIRECTION = 4,
    COM_INTERFACE_REDIRECTION = 5,
    COM_TYPE_LIBRARY_REDIRECTION = 6,
    COM_PROGID_REDIRECTION = 7,
    GLOBAL_OBJECT_RENAME_TABLE = 8,
    CLR_SURROGATES = 9,
    APPLICATION_SETTINGS = 10,
    COMPATIBILITY_INFO = 11,
}
