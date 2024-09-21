//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Safe handle which represents a kernel handle.
    /// </summary>
    public class SafeKernelObjectHandle : SafeHandle
    {
        private string _type_name;

        private SafeKernelObjectHandle()
            : base(IntPtr.Zero, true)
        {
        }

        internal SafeKernelObjectHandle(int pseudo_handle)
            : this(new IntPtr(pseudo_handle), false)
        {
            PseudoHandle = true;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="handle">An existing kernel handle.</param>
        /// <param name="owns_handle">True to own the kernel handle.</param>
        public SafeKernelObjectHandle(IntPtr handle, bool owns_handle)
          : base(IntPtr.Zero, owns_handle)
        {
            SetHandle(handle);
        }

        /// <summary>
        /// Overridden ReleaseHandle method.
        /// </summary>
        /// <returns>True if successfully released the handle.</returns>
        protected override bool ReleaseHandle()
        {
            if (PseudoHandle)
                return false;
            if (NtSystemCalls.NtClose(handle).IsSuccess())
            {
                handle = IntPtr.Zero;
                return true;
            }
            return false;
        }

        internal bool PseudoHandle { get; }

        /// <summary>
        /// Overridden IsInvalid method.
        /// </summary>
        public override bool IsInvalid => handle.ToInt64() <= 0;

        /// <summary>
        /// Get a handle which represents NULL.
        /// </summary>
        public static SafeKernelObjectHandle Null => new SafeKernelObjectHandle(IntPtr.Zero, false);

        private ObjectHandleInformation QueryHandleInformation()
        {
            using (var buffer = new SafeStructureInOutBuffer<ObjectHandleInformation>())
            {
                NtSystemCalls.NtQueryObject(this, ObjectInformationClass.ObjectHandleFlagInformation,
                    buffer, buffer.Length, out int return_length).ToNtException();
                return buffer.Result;
            }
        }

        private void SetHandleInformation(ObjectHandleInformation handle_info)
        {
            using (var buffer = handle_info.ToBuffer())
            {
                NtSystemCalls.NtSetInformationObject(
                    this, ObjectInformationClass.ObjectHandleFlagInformation,
                    buffer, buffer.Length).ToNtException();
            }
        }

        /// <summary>
        /// Get or set whether the handle is inheritable.
        /// </summary>
        public bool Inherit
        {
            get
            {
                return QueryHandleInformation().Inherit;
            }

            set
            {
                var handle_info = QueryHandleInformation();
                handle_info.Inherit = value;
                SetHandleInformation(handle_info);
            }
        }

        /// <summary>
        /// Get or set whether the handle is protected from closing.
        /// </summary>
        public bool ProtectFromClose
        {
            get
            {
                return QueryHandleInformation().ProtectFromClose;
            }

            set
            {
                var handle_info = QueryHandleInformation();
                handle_info.ProtectFromClose = value;
                SetHandleInformation(handle_info);
            }
        }

        /// <summary>
        /// Get the NT type name for this handle.
        /// </summary>
        /// <returns>The NT type name.</returns>
        public string NtTypeName
        {
            get
            {
                if (_type_name == null)
                {
                    using (var type_info = new SafeStructureInOutBuffer<ObjectTypeInformation>(1024, true))
                    {
                        NtSystemCalls.NtQueryObject(this,
                            ObjectInformationClass.ObjectTypeInformation, type_info,
                            type_info.Length, out int return_length).ToNtException();
                        _type_name = type_info.Result.Name.ToString();
                    }
                }
                return _type_name;
            }
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The handle as a string.</returns>
        public override string ToString()
        {
            return $"0x{DangerousGetHandle().ToInt64():X}";
        }
    }
}
