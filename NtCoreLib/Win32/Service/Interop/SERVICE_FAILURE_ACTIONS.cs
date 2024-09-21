//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

#nullable enable

using NtCoreLib.Native.SafeBuffers;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Service.Interop;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct SERVICE_FAILURE_ACTIONS
{
    public int dwResetPeriod;
    public string? lpRebootMsg;
    public string? lpCommand;
    public int cActions;
    public SafeHGlobalBuffer lpsaActions;
}
