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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    public class ProcessAttribute : IDisposable
    {
        const uint NumberMask = 0x0000FFFF;
        const uint ThreadOnly = 0x00010000; // Attribute may be used with thread creation
        const uint InputOnly = 0x00020000; // Attribute is input only
        const uint Additive = 0x00040000; // Attribute may be "accumulated," e.g. bitmasks, counters, etc

        SafeHandle _handle;
        ProcessAttributeNum _attribute_num;
        bool _thread;
        bool _input;
        bool _additive;
        IntPtr _valueptr;
        IntPtr _size;
        IntPtr _return_length;

        private ProcessAttribute(ProcessAttributeNum num, bool thread, bool input, bool additive, IntPtr valueptr, int size, IntPtr return_length)
        {
            _attribute_num = num;
            _thread = thread;
            _input = input;
            _additive = additive;
            _valueptr = valueptr;
            _size = new IntPtr(size);
            _return_length = return_length;
        }

        private ProcessAttribute(ProcessAttributeNum num, bool thread, bool input, bool additive, SafeHandle handle, int size, IntPtr return_length) :
           this(num, thread, input, additive, handle.DangerousGetHandle(), size, return_length)
        {
            _handle = handle;
        }

        private ProcessAttribute(ProcessAttributeNum num, bool thread, bool input, bool additive, SafeHGlobalBuffer handle) :
          this(num, thread, input, additive, handle, handle.Length, IntPtr.Zero)
        {
        }

        private ProcessAttribute(ProcessAttributeNum num, bool thread, bool input, bool additive, SafeKernelObjectHandle handle) :
            this(num, thread, input, additive, handle, IntPtr.Size, IntPtr.Zero)
        {
        }

        public ProcessAttributeNative GetNativeAttribute()
        {
            IntPtr valueptr = _handle != null ? _handle.DangerousGetHandle() : _valueptr;
            return new ProcessAttributeNative(((uint)_attribute_num & NumberMask)
              | (_thread ? ThreadOnly : 0) | (_input ? InputOnly : 0) | (_additive ? Additive : 0), valueptr, _size, _return_length);
        }

        public static ProcessAttribute ImageName(string image_name)
        {
            SafeHGlobalBuffer name = new SafeHGlobalBuffer(Marshal.StringToHGlobalUni(image_name), image_name.Length * 2, true);
            return new ProcessAttribute(ProcessAttributeNum.ImageName, false, true, false,
                  name);
        }

        public static ProcessAttribute ParentProcess(SafeKernelObjectHandle parent_process)
        {
            return new ProcessAttribute(ProcessAttributeNum.ParentProcess,
              false, true, true, NtObject.DuplicateHandle(parent_process));
        }

        public static ProcessAttribute Token(SafeKernelObjectHandle token)
        {
            return new ProcessAttribute(ProcessAttributeNum.Token,
              false, true, true, NtObject.DuplicateHandle(token));
        }

        public static ProcessAttribute ImageInfo(SafeStructureInOutBuffer<SectionImageInformation> image_information)
        {
            return new ProcessAttribute(ProcessAttributeNum.ImageInfo, false, false, false, image_information);
        }

        public static ProcessAttribute ClientId(SafeStructureInOutBuffer<ClientId> client_id)
        {
            return new ProcessAttribute(ProcessAttributeNum.ClientId, true, false, false, client_id);
        }

        public static ProcessAttribute ChildProcess(bool child_process_restricted, bool child_process_override)
        {
            ChildProcessMitigationFlags flags = child_process_restricted ?
                ChildProcessMitigationFlags.Restricted : ChildProcessMitigationFlags.None;
            if (child_process_override)
                flags |= ChildProcessMitigationFlags.Override;
            return ChildProcess(flags);
        }

        public static ProcessAttribute ChildProcess(ChildProcessMitigationFlags flags)
        {
            int value = (int)flags;
            return new ProcessAttribute(ProcessAttributeNum.ChildProcess, false, true, false, value.ToBuffer());
        }

        public static ProcessAttribute ProtectionLevel(PsProtectedType type, PsProtectedSigner signer, bool audit)
        {
            return ProtectionLevel(new PsProtection(type, signer, audit));
        }

        public static ProcessAttribute ProtectionLevel(PsProtection protection)
        {
            return new ProcessAttribute(ProcessAttributeNum.ProtectionLevel, false, true, true, 
                new IntPtr(protection.Level), 1, IntPtr.Zero);
        }

        public static ProcessAttribute HandleList(IEnumerable<SafeHandle> handles)
        {
            return new ProcessAttribute(ProcessAttributeNum.HandleList, false, true, false,
              new SafeHandleListHandle(handles.Select(h => NtObject.DuplicateHandle(h.ToSafeKernelHandle()))));
        }

        public static ProcessAttribute SecureProcess(NtProcessTrustletConfig trustlet_config)
        {
            return new ProcessAttribute(ProcessAttributeNum.SecureProcess, false, true, false,
                  trustlet_config.ToArray().ToBuffer());
        }

        public static ProcessAttribute JobList(IEnumerable<NtJob> jobs)
        {
            return new ProcessAttribute(ProcessAttributeNum.JobList, false, true, false,
              SafeHandleListHandle.CreateAndDuplicate(jobs));
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (_handle != null)
                {
                    _handle.Close();
                    _handle = null;
                }

                disposedValue = true;
            }
        }

        ~ProcessAttribute()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    };

    public sealed class ProcessAttributeList : SafeStructureInOutBuffer<PsAttributeList>
    {
        private ProcessAttributeList(ProcessAttributeNative[] attributes)
            : base(Marshal.SizeOf(typeof(ProcessAttributeNative)) * attributes.Length, true)
        {
            var result = Result;
            result.TotalLength = new IntPtr(Length);
            Result = result;
            Data.WriteArray(0, attributes, 0, attributes.Length);
        }

        private ProcessAttributeList(IntPtr buffer, int length, bool owns_handle)
            : base(buffer, length, owns_handle)
        {
        }

        public ProcessAttributeList(IEnumerable<ProcessAttribute> attributes)
            : this(attributes.Select(a => a.GetNativeAttribute()).ToArray())
        {
        }

        new public static ProcessAttributeList Null => new ProcessAttributeList(IntPtr.Zero, 0, false);

        public static ProcessAttributeList Create(IEnumerable<ProcessAttribute> attributes)
        {
            if (attributes == null || !attributes.Any())
            {
                return Null;
            }
            return new ProcessAttributeList(attributes);
        }
    }
#pragma warning restore 1591
}
