//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace NtApiDotNet
{
#pragma warning disable 1591
    /// <summary>
    /// A safe handle to an allocated global buffer.
    /// </summary>
    public class SafeHGlobalBuffer : SafeBuffer
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">Size of the buffer to allocate.</param>
        public SafeHGlobalBuffer(int length)
          : this(length, length)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="allocation_length">The length of data to allocate.</param>
        /// <param name="total_length">The total length to reflect in the Length property.</param>
        protected SafeHGlobalBuffer(int allocation_length, int total_length) 
            : this(Marshal.AllocHGlobal(allocation_length), total_length, true)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">Size of the buffer.</param>
        /// <param name="buffer">An existing pointer to an existing HGLOBAL allocated buffer.</param>
        /// <param name="owns_handle">Specify whether safe handle owns the buffer.</param>
        public SafeHGlobalBuffer(IntPtr buffer, int length, bool owns_handle)
          : base(owns_handle)
        {
            Length = length;
            Initialize((ulong)length);
            SetHandle(buffer);
        }

        public static SafeHGlobalBuffer Null { get { return new SafeHGlobalBuffer(IntPtr.Zero, 0, false); } }

        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.None)]
        public virtual void Resize(int new_length)
        {
            IntPtr free_handle = IntPtr.Zero;
            try
            {
                byte[] old_data = new byte[Length];
                Marshal.Copy(handle, old_data, 0, Length);
                free_handle = Marshal.AllocHGlobal(new_length);
                Marshal.Copy(old_data, 0, free_handle, Math.Min(new_length, Length));
                free_handle = Interlocked.Exchange(ref handle, free_handle);
                Length = new_length;
                Initialize((ulong)new_length);                 
            }
            finally
            {
                if (free_handle != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(free_handle);
                }
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="data">Initialization data for the buffer.</param>
        public SafeHGlobalBuffer(byte[] data) : this(data.Length)
        {
            Marshal.Copy(data, 0, handle, data.Length);
        }

        public int Length
        {
            get; private set;
        }

        /// <summary>
        /// Get the length as an IntPtr
        /// </summary>
        public IntPtr LengthIntPtr
        {
            get { return new IntPtr(Length); }
        }

        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                Marshal.FreeHGlobal(handle);
                handle = IntPtr.Zero;
            }
            return true;
        }

        /// <summary>
        /// Convert the safe handle to an array of bytes.
        /// </summary>
        /// <returns>The data contained in the allocaiton.</returns>
        public byte[] ToArray()
        {
            return ReadBytes(Length);
        }

        public string ReadUnicodeString(ulong byte_offset, int count)
        {
            char[] ret = new char[count];
            ReadArray(byte_offset, ret, 0, count);
            return new string(ret);
        }

        public string ReadUnicodeString(int count)
        {
            return ReadUnicodeString(0, count);
        }

        public void WriteUnicodeString(ulong byte_offset, string value)
        {
            char[] chars = value.ToCharArray();
            WriteArray(byte_offset, chars, 0, chars.Length);
        }

        public void WriteUnicodeString(string value)
        {
            WriteUnicodeString(0, value);
        }

        public byte[] ReadBytes(ulong byte_offset, int count)
        {
            byte[] ret = new byte[count];
            ReadArray(byte_offset, ret, 0, count);
            return ret;
        }

        public byte[] ReadBytes(int count)
        {
            return ReadBytes(0, count);
        }

        public void WriteBytes(ulong byte_offset, byte[] data)
        {
            WriteArray(byte_offset, data, 0, data.Length);
        }

        public void WriteBytes(byte[] data)
        {
            WriteBytes(0, data);
        }

        public SafeStructureInOutBuffer<T> GetStructAtOffset<T>(int offset) where T : new()
        {
            int length_left = Length - offset;
            int struct_size = Marshal.SizeOf(typeof(T));
            if (length_left < struct_size)
            {
                throw new ArgumentException("Invalid length for structure");
            }

            return new SafeStructureInOutBuffer<T>(handle + offset, length_left, false);
        }
    }

    /// <summary>
    /// Safe handle for an in/out structure buffer.
    /// </summary>
    /// <typeparam name="T">The type of structure as the base of the memory allocation.</typeparam>
    public class SafeStructureInOutBuffer<T> : SafeHGlobalBuffer where T : new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">Structure value to initialize the buffer.</param>
        public SafeStructureInOutBuffer(T value)
            : this(value, 0, true)
        {
        }

        /// <summary>
        /// Constructor, initializes buffer with a default structure.
        /// </summary>        
        public SafeStructureInOutBuffer()
            : this(new T(), 0, true)
        {
        }

        public SafeStructureInOutBuffer(IntPtr buffer, int length, bool owns_handle) 
            : base(buffer, length, owns_handle)
        {
        }

        // Private constructor for Null buffer.
        protected SafeStructureInOutBuffer(int dummy_length) : base(IntPtr.Zero, dummy_length, false)
        {
        }

        new public static SafeStructureInOutBuffer<T> Null { get { return new SafeStructureInOutBuffer<T>(0); } }

        /// <summary>
        /// Constructor, initializes buffer with a default structure.
        /// </summary>        
        /// <param name="additional_size">Additional data to add to structure buffer.</param>
        /// <param name="add_struct_size">If true additional_size is added to structure size, otherwise reflects the total size.</param>
        public SafeStructureInOutBuffer(int additional_size, bool add_struct_size)
            : this(new T(), additional_size, add_struct_size)
        {
        }

        private static int GetStructDataOffset()
        {
            DataStartAttribute attr = typeof(T).GetCustomAttribute<DataStartAttribute>();
            if (attr != null)
            {
                return Marshal.OffsetOf(typeof(T), attr.FieldName).ToInt32();            
            }
            return Marshal.SizeOf(typeof(T));
        }

        private static int GetTotalLength(int additional_size, bool add_struct_size)
        {
            if (add_struct_size)
            {
                int data_offset = GetStructDataOffset();
                return data_offset + additional_size;
            }
            return additional_size;
        }

        private static int GetAllocationLength(int length)
        {
            // Always ensure we at least allocate the entire structure length.
            int struct_length = Marshal.SizeOf(typeof(T));
            if (length < struct_length)
                return struct_length;
            return length;
        }

        private SafeStructureInOutBuffer(T value, int total_length) 
            : base(GetAllocationLength(total_length), total_length)
        {
            Marshal.StructureToPtr(value, handle, false);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">Structure value to initialize the buffer.</param>
        /// <param name="additional_size">Additional data to add to structure buffer.</param>
        /// <param name="add_struct_size">If true additional_size is added to structure size, otherwise reflects the total size.</param>
        public SafeStructureInOutBuffer(T value, int additional_size, bool add_struct_size)
            : this(value, GetTotalLength(additional_size, add_struct_size))
        {
        }

        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                Marshal.DestroyStructure(handle, typeof(T));
            }
            return base.ReleaseHandle();
        }

        /// <summary>
        /// Convert the buffer back to a structure.
        /// </summary>
        public virtual T Result
        {
            get
            {
                if (IsClosed || IsInvalid)
                    throw new ObjectDisposedException("handle");
                
                return (T)Marshal.PtrToStructure(handle, typeof(T));
            }
        }

        /// <summary>
        /// Get a reference to the additional data.
        /// </summary>
        public SafeHGlobalBuffer Data
        {
            get
            {
                if (IsClosed || IsInvalid)
                    throw new ObjectDisposedException("handle");

                int size = GetStructDataOffset();
                int length = Length - size;
                return new SafeHGlobalBuffer(handle + size, length < 0 ? 0 : length, false);
            }
        }
    }

    public class SafeStructureArrayBuffer<T> : SafeStructureInOutBuffer<T> where T : new()
    {
        private int _array_length;

        private static FieldInfo GetDataStartField()
        {
            DataStartAttribute attr = typeof(T).GetCustomAttribute<DataStartAttribute>();
            if (attr != null)
            {
                return typeof(T).GetField(attr.FieldName);
            }
            return null;
        }

        private static Array GetArray(T value)
        {
            FieldInfo fi = GetDataStartField();
            if (fi == null)
            {
                throw new ArgumentException("Structure must contain a data start field");
            }
            Type field_type = fi.FieldType;
            if (!field_type.IsArray && !field_type.GetElementType().IsValueType)
            {
                throw new ArgumentException("Data start field must be an array of a value type");
            }

            Array array = (Array)fi.GetValue(value);
            if (array == null)
            {
                throw new ArgumentNullException("Data array must not be null");
            }
            return array;
        }

        private static int CalculateDataLength(Array array)
        {
            return array.Length * Marshal.SizeOf(array.GetType().GetElementType());
        }

        private SafeStructureArrayBuffer(T value, Array array) : base(value, CalculateDataLength(array), true)
        {
            _array_length = array.Length;
        }

        public SafeStructureArrayBuffer(T value) : this(value, GetArray(value))
        {
        }

        protected SafeStructureArrayBuffer(int dummy_length) : base(dummy_length)
        {
        }

        new public static SafeStructureArrayBuffer<T> Null { get { return new SafeStructureArrayBuffer<T>(0); } }

        public override T Result
        {
            get
            {
                T result = base.Result;
                FieldInfo fi = GetDataStartField();
                Type elem_type = fi.FieldType.GetElementType();
                Array array = Array.CreateInstance(elem_type, _array_length);
                IntPtr current_ptr = Data.DangerousGetHandle();
                int elem_size = Marshal.SizeOf(elem_type);
                for (int i = 0; i < _array_length; ++i)
                {
                    array.SetValue(Marshal.PtrToStructure(current_ptr, elem_type), i);
                    current_ptr += elem_size;
                }
                fi.SetValue(result, array);
                return result;
            }
        }
    }    

    public sealed class SafeKernelObjectHandle
      : SafeHandle
    {
        private SafeKernelObjectHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public SafeKernelObjectHandle(IntPtr handle, bool owns_handle)
          : base(IntPtr.Zero, owns_handle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            if (NtSystemCalls.NtClose(this.handle).IsSuccess())
            {
                this.handle = IntPtr.Zero;
                return true;
            }
            return false;
        }

        public override bool IsInvalid
        {
            get
            {
                return this.handle.ToInt64() <= 0;
            }
        }

        public static SafeKernelObjectHandle Null
        {
            get { return new SafeKernelObjectHandle(IntPtr.Zero, false); }
        }
    }

    public sealed class SafeHandleListHandle : SafeHGlobalBuffer
    {
        private SafeKernelObjectHandle[] _handles;

        public SafeHandleListHandle(IEnumerable<SafeKernelObjectHandle> handles)
          : base(IntPtr.Size * handles.Count())
        {
            _handles = handles.ToArray();
            IntPtr buffer = handle;
            for (int i = 0; i < _handles.Length; ++i)
            {
                Marshal.WriteIntPtr(buffer, _handles[i].DangerousGetHandle());
                buffer += IntPtr.Size;
            }
        }

        protected override bool ReleaseHandle()
        {
            foreach (SafeKernelObjectHandle handle in _handles)
            {
                handle.Close();
            }
            _handles = new SafeKernelObjectHandle[0];
            return base.ReleaseHandle();
        }
    }

    public sealed class SafeStringBuffer : SafeHGlobalBuffer
    {
        public SafeStringBuffer(string str) : base(Encoding.Unicode.GetBytes(str + "\0"))
        {
        }
    }

    public sealed class SafeSecurityIdentifierHandle : SafeHGlobalBuffer
    {
        private static byte[] SidToArray(SecurityIdentifier sid)
        {
            byte[] ret = new byte[sid.BinaryLength];
            sid.GetBinaryForm(ret, 0);
            return ret;
        }

        public SafeSecurityIdentifierHandle(SecurityIdentifier sid) : base(SidToArray(sid))
        {
        }
    }

    public sealed class SafeSecurityDescriptor : SafeHGlobalBuffer
    {
        private static byte[] SdToArray(GenericSecurityDescriptor sd)
        {
            byte[] ret = new byte[sd.BinaryLength];
            sd.GetBinaryForm(ret, 0);
            return ret;
        }

        public SafeSecurityDescriptor(GenericSecurityDescriptor sd) : base(SdToArray(sd))
        {
        }
    }

    public sealed class SafeLocalAllocHandle : SafeHandle
    {
        [DllImport("kernel32.dll", SetLastError =true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        protected override bool ReleaseHandle()
        {
            return LocalFree(handle) == IntPtr.Zero;
        }

        public SafeLocalAllocHandle(IntPtr handle, bool owns_handle) : base(IntPtr.Zero, owns_handle)
        {
            SetHandle(handle);
        }

        public SafeLocalAllocHandle() : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid
        {
            get
            {
                return handle == IntPtr.Zero;
            }
        }
    }

    /// <summary>
    /// Some simple utilities to create structure buffers.
    /// </summary>
    public static class BufferUtils
    {
        /// <summary>
        /// Create a buffer based on a passed type.
        /// </summary>
        /// <typeparam name="T">The type to use in the structure buffer.</typeparam>
        /// <param name="value">The value to initialize the buffer with.</param>
        /// <param name="additional_size">Additional byte data after the structure.</param>
        /// <param name="add_struct_size">Indicates if additional_size includes the structure size or not.</param>
        /// <returns>The new structure buffer.</returns>
        public static SafeStructureInOutBuffer<T> CreateBuffer<T>(T value, int additional_size, bool add_struct_size) where T : new()
        {
            return new SafeStructureInOutBuffer<T>(value, additional_size, add_struct_size);
        }

        /// <summary>
        /// Create a buffer based on a passed type.
        /// </summary>
        /// <typeparam name="T">The type to use in the structure buffer.</typeparam>
        /// <param name="value">The value to initialize the buffer with.</param>
        /// <returns>The new structure buffer.</returns>
        public static SafeStructureInOutBuffer<T> CreateBuffer<T>(T value) where T : new()
        {
            return new SafeStructureInOutBuffer<T>(value);
        }

        /// <summary>
        /// Create a buffer based on a passed type.
        /// </summary>
        /// <typeparam name="T">The type to use in the structure buffer.</typeparam>
        /// <param name="value">The value to initialize the buffer with.</param>
        /// <returns>The new structure buffer.</returns>
        public static SafeStructureInOutBuffer<T> ToBuffer<T>(this T value) where T : new()
        {
            return CreateBuffer(value, 0, true);
        }

        /// <summary>
        /// Create a buffer based on a passed type.
        /// </summary>
        /// <typeparam name="T">The type to use in the structure buffer.</typeparam>
        /// <param name="value">The value to initialize the buffer with.</param>
        /// <param name="additional_size">Additional byte data after the structure.</param>
        /// <param name="add_struct_size">Indicates if additional_size includes the structure size or not.</param>
        /// <returns>The new structure buffer.</returns>
        public static SafeStructureInOutBuffer<T> ToBuffer<T>(this T value, int additional_size, bool add_struct_size) where T : new()
        {
            return CreateBuffer(value, additional_size, add_struct_size);
        }

        /// <summary>
        /// Create an array buffer based on a passed type.
        /// </summary>
        /// <typeparam name="T">The type to use in the structure buffer.</typeparam>
        /// <param name="value">The value to initialize the buffer with.</param>
        /// <returns>The new array buffer.</returns>
        public static SafeStructureArrayBuffer<T> CreateArrayBuffer<T>(T value) where T : new()
        {
            return new SafeStructureArrayBuffer<T>(value);
        }

        /// <summary>
        /// Create an array buffer based on a passed type.
        /// </summary>
        /// <typeparam name="T">The type to use in the structure buffer.</typeparam>
        /// <param name="value">The value to initialize the buffer with.</param>
        /// <returns>The new array buffer.</returns>
        public static SafeStructureArrayBuffer<T> ToArrayBuffer<T>(this T value) where T : new()
        {
            return CreateArrayBuffer(value);
        }
    }

    /// <summary>
    /// Safe SID buffer.
    /// </summary>
    /// <remarks>This is used to return values from the RTL apis which need to be freed using RtlFreeSid</remarks>
    public sealed class SafeSidBufferHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSidBufferHandle(IntPtr sid, bool owns_handle) : base(owns_handle)
        {
            SetHandle(sid);
        }

        public SafeSidBufferHandle() : base(true)
        {
        }

        public int Length
        {
            get { return NtRtl.RtlLengthSid(handle); }
        }

        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                NtRtl.RtlFreeSid(handle);
                handle = IntPtr.Zero;
            }
            return true;
        }
    }


    public class SafeSecurityObjectHandle : SafeBuffer
    {
        public SafeSecurityObjectHandle() : base(true)
        {
            Initialize(0);
        }

        protected override bool ReleaseHandle()
        {
            return NtRtl.RtlDeleteSecurityObject(ref handle).IsSuccess();
        }
    }

    public class SafeIoStatusBuffer : SafeStructureInOutBuffer<IoStatus>
    {
    }

#pragma warning restore 1591
}
