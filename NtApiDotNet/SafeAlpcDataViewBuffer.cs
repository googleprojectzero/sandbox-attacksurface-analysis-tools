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

namespace NtApiDotNet
{
    /// <summary>
    /// Safe buffer for an ALPC data view.
    /// </summary>
    public class SafeAlpcDataViewBuffer : SafeBufferGeneric
    {
        internal SafeAlpcDataViewBuffer(IntPtr view_base, long view_size,
            SafeAlpcPortSectionHandle section_handle, AlpcDataViewAttrFlags flags,
            bool owns_handle) : this(view_base, view_size, owns_handle)
        {
            Flags = flags;
            // If creating a secure buffer then touch all pages. This is IMHO incredibly unintuitive.
            if (Flags.HasFlag(AlpcDataViewAttrFlags.Secure))
            {
                int page_size = NtSystemInfo.PageSize;
                long page_count = (view_size + page_size - 1) / page_size;
                ulong offset = 0;
                for (long i = 0; i < page_count; ++i)
                {
                    Write(offset, Read<byte>(offset));
                    offset += (uint)page_size;
                }
            }
            SectionHandle = section_handle;
        }

        internal SafeAlpcDataViewBuffer(IntPtr view_base, long view_size, bool owns_handle)
            : base(view_base, view_size, owns_handle, true)
        {
        }

        internal SafeAlpcDataViewBuffer() 
            : base(IntPtr.Zero, 0, false)
        {
        }

        /// <summary>
        /// Flags for the data view.
        /// </summary>
        public AlpcDataViewAttrFlags Flags { get; }

        /// <summary>
        /// Get the port section handle.
        /// </summary>
        public SafeAlpcPortSectionHandle SectionHandle { get; }

        /// <summary>
        /// Convert the section view to a message attribute.
        /// </summary>
        /// <returns>The message attribute.</returns>
        public AlpcDataViewMessageAttribute ToMessageAttribute()
        {
            return new AlpcDataViewMessageAttribute(DangerousGetHandle().ToInt64(), 
                LongLength, SectionHandle.DangerousGetHandle().ToInt64(), Flags);
        }

        /// <summary>
        /// Release the data view handle.
        /// </summary>
        /// <returns>True if successfully released.</returns>
        protected override bool ReleaseHandle()
        {
            if (SectionHandle == null || SectionHandle.IsClosed 
                || SectionHandle.Port == null || SectionHandle.Port.Handle.IsClosed)
            {
                return false;
            }
            return NtSystemCalls.NtAlpcDeleteSectionView(SectionHandle.Port.Handle, 0, DangerousGetHandle()).IsSuccess();
        }
    }
}
