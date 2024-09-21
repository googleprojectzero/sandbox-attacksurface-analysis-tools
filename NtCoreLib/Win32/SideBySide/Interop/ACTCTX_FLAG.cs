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

namespace NtCoreLib.Win32.SideBySide.Interop;

internal enum ACTCTX_FLAG
{
    None = 0,
    ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID = 1,
    ACTCTX_FLAG_LANGID_VALID = 2,
    ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID = 4,
    ACTCTX_FLAG_RESOURCE_NAME_VALID = 8,
    ACTCTX_FLAG_SET_PROCESS_DEFAULT = 0x10,
    ACTCTX_FLAG_APPLICATION_NAME_VALID = 0x20,
    ACTCTX_FLAG_SOURCE_IS_ASSEMBLYREF = 0x40,
    ACTCTX_FLAG_HMODULE_VALID = 0x80
}
