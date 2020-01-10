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

using Microsoft.Win32.SafeHandles;
using System;

namespace NtApiDotNet
{
#pragma warning disable 1591

    public sealed class SafeProcessParametersHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeProcessParametersHandle(IntPtr proc_params, bool owns_handle) : base(owns_handle)
        {
            SetHandle(proc_params);
        }

        public SafeProcessParametersHandle() : base(true)
        {
        }

        public static SafeProcessParametersHandle Null
        {
            get => new SafeProcessParametersHandle(IntPtr.Zero, false);
        }

        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                NtRtl.RtlDestroyProcessParameters(handle);
                handle = IntPtr.Zero;
            }
            return true;
        }

        private static UnicodeString GetString(string s)
        {
            return s != null ? new UnicodeString(s) : null;
        }

        public static NtResult<SafeProcessParametersHandle> Create(
                string image_path_name,
                string dll_path,
                string current_directory,
                string command_line,
                byte[] environment,
                string window_title,
                string desktop_info,
                string shell_info,
                string runtime_data,
                CreateProcessParametersFlags flags,
                bool throw_on_error)
        {
            return NtRtl.RtlCreateProcessParametersEx(out IntPtr ret, GetString(image_path_name), GetString(dll_path), GetString(current_directory),
              GetString(command_line), environment, GetString(window_title), GetString(desktop_info), GetString(shell_info),
              GetString(runtime_data), flags).CreateResult(throw_on_error, () => new SafeProcessParametersHandle(ret, true));
        }

        public static SafeProcessParametersHandle Create(
                string image_path_name,
                string dll_path,
                string current_directory,
                string command_line,
                byte[] environment,
                string window_title,
                string desktop_info,
                string shell_info,
                string runtime_data,
                CreateProcessParametersFlags flags)
        {
            return Create(image_path_name, dll_path, current_directory, command_line, environment, 
                window_title, desktop_info, shell_info, runtime_data, flags, true).Result;
        }
    }

#pragma warning restore 1591
}
