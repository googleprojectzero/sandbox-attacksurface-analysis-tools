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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Utilities.Collections;
using System;

namespace NtCoreLib.Win32.Process.Interop;

internal class SafeProcThreadAttributeListBuffer : SafeHGlobalBuffer
{
    private readonly DisposableList<IDisposable> _values = new();

    private static int GetAttributeListSize(int count)
    {
        IntPtr size = IntPtr.Zero;
        NativeMethods.InitializeProcThreadAttributeList(IntPtr.Zero, count, 0, ref size);
        return size.ToInt32();
    }

    public SafeProcThreadAttributeListBuffer(int count) : base(GetAttributeListSize(count))
    {
        IntPtr size = new(Length);
        NativeMethods.InitializeProcThreadAttributeList(handle, count, 0, ref size).ToNtException(true);
    }

    public void AddAttribute<T>(IntPtr attribute, T value) where T : struct
    {
        AddAttributeBuffer(attribute, _values.AddResource(value.ToBuffer()));
    }

    public void AddAttribute(IntPtr attribute, byte[] value)
    {
        AddAttributeBuffer(attribute, _values.AddResource(new SafeHGlobalBuffer(value)));
    }

    public void AddAttributeBuffer(IntPtr attribute, SafeHGlobalBuffer value)
    {
        NativeMethods.UpdateProcThreadAttribute(handle, 0, attribute, value.DangerousGetHandle(),
            new IntPtr(value.Length), IntPtr.Zero, IntPtr.Zero).ToNtException(true);
    }

    protected override bool ReleaseHandle()
    {
        _values?.Dispose();
        if (!IsInvalid)
        {
            bool ret = NativeMethods.DeleteProcThreadAttributeList(handle);
            return base.ReleaseHandle() && ret;
        }

        return false;
    }
}

