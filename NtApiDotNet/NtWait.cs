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

using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    public enum WaitType
    {
        WaitAll,
        WaitAny
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtWaitForSingleObject(
          SafeKernelObjectHandle Handle,
          bool Alertable,
          LargeInteger Timeout
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtWaitForMultipleObjects(int HandleCount, 
            [Out] SafeKernelObjectHandle[] Handles, WaitType WaitType, bool Alertable, LargeInteger Timeout);
    }
#pragma warning disable 1591

    public class NtWait
    {
        private static LargeInteger LongToTimeout(long timeout)
        {
            return timeout == Infinite ? null : new LargeInteger(timeout);
        }

        public static NtStatus Wait(NtObject obj, bool alertable, long timeout)
        {
            return NtSystemCalls.NtWaitForSingleObject(obj.Handle, alertable, LongToTimeout(timeout)).ToNtException();
        }

        public static NtStatus Wait(IEnumerable<NtObject> objs, bool alertable, bool wait_all, long timeout)
        {
            SafeKernelObjectHandle[] handles = objs.Select(o => o.Handle).ToArray();
            return NtSystemCalls.NtWaitForMultipleObjects(handles.Length, handles,
                wait_all ? WaitType.WaitAll : WaitType.WaitAny, alertable, LongToTimeout(timeout)).ToNtException();
        }

        public const long Infinite = long.MinValue;
    }
}
