//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    [Flags]
    public enum DebugAccessRights : uint
    {
        ReadEvent = 0x1,
        ProcessAssign = 0x2,
        SetInformation = 0x4,
        QueryInformation = 0x8,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDebugActiveProcess(SafeKernelObjectHandle ProcessHandle, SafeKernelObjectHandle DebugHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateDebugObject(out SafeKernelObjectHandle DebugHandle, DebugAccessRights DesiredAccess, ObjectAttributes ObjectAttributes, int Flags);
    }

    public class NtDebug : NtObjectWithDuplicate<NtDebug, GenericAccessRights>
    {
        internal NtDebug(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        public static NtDebug Create(string name, NtObject root)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, DebugAccessRights.MaximumAllowed);
            }
        }

        public static NtDebug Create(ObjectAttributes object_attributes, DebugAccessRights desired_access)
        {
            SafeKernelObjectHandle handle;
            StatusToNtException(NtSystemCalls.NtCreateDebugObject(out handle, desired_access, object_attributes, 0));
            return new NtDebug(handle);
        }

        public static NtDebug Create()
        {
            return Create(null, null);
        }
    }
}
