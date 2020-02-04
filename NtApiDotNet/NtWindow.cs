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
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to represent a Window.
    /// </summary>
    public sealed class NtWindow
    {
        /// <summary>
        /// The Window Handle.
        /// </summary>
        public IntPtr Handle { get; }

        /// <summary>
        /// Get Process ID for the Window.
        /// </summary>
        public int ProcessId => Query(QueryWindowType.ProcessId);

        /// <summary>
        /// Get the Thread ID for the Window.
        /// </summary>
        public int ThreadId => Query(QueryWindowType.ThreadId);

        /// <summary>
        /// Get the real owner Process ID of the Window.
        /// </summary>
        public int Owner => Query(QueryWindowType.Owner);

        /// <summary>
        /// Get the class name for the Window.
        /// </summary>
        public string ClassName => GetClassName(false);

        /// <summary>
        /// Get the NULL window handle.
        /// </summary>
        public static NtWindow Null => new NtWindow(IntPtr.Zero);

        /// <summary>
        /// Get all Top Level windows.
        /// </summary>
        public static IEnumerable<NtWindow> Windows => GetWindows(null, Null, 0, 1, 0);

        internal NtWindow(IntPtr handle)
        {
            Handle = handle;
        }

        internal int Query(QueryWindowType query)
        {
            return NtSystemCalls.NtUserQueryWindow(Handle, query);
        }

        internal string GetClassName(bool real_name)
        {
            using (var str = new UnicodeStringAllocated())
            {
                int length = NtSystemCalls.NtUserGetClassName(Handle, real_name, str);
                if (length == 0)
                {
                    throw new NtException(NtObjectUtils.MapDosErrorToStatus());
                }

                str.String.Length = (ushort)(length * 2);

                return str.ToString();
            }
        }

        internal static IEnumerable<NtWindow> GetWindows(NtDesktop desktop, NtWindow parent,
            int flag1, int flag2, int thread_id)
        {
            int count = 64;
            while (true)
            {
                IntPtr[] handles = new IntPtr[count];
                NtStatus status = NtSystemCalls.NtUserBuildHwndList(desktop.GetHandle(), parent.Handle, flag1, 
                    flag2, thread_id, handles.Length, handles, out int required_count);
                if (status.IsSuccess())
                {
                    return handles.Take(required_count).Select(i => new NtWindow(i));
                }
                if (status != NtStatus.STATUS_BUFFER_TOO_SMALL || count > required_count)
                {
                    throw new NtException(status);
                }
                count = required_count;
            }
        }
    }
}
