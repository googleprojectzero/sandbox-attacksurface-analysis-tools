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

using System;

namespace NtCoreLib.Win32.Process.Interop;

internal class ScopedDebugObject : IDisposable
{
    private readonly NtDebug _debug_object;
    private readonly IntPtr _old_debug_object_handle;

    public ScopedDebugObject(NtDebug debug_object)
    {
        _debug_object = debug_object;
        _old_debug_object_handle = NtDbgUi.DbgUiGetThreadDebugObject();
        NtDbgUi.DbgUiSetThreadDebugObject(debug_object.Handle.DangerousGetHandle());
    }

    public void Dispose()
    {
        NtDbgUi.DbgUiSetThreadDebugObject(_old_debug_object_handle);
    }
}
