//  Copyright 2018 Google Inc. All Rights Reserved.
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
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Ndr
{

    internal class CrossBitnessTypeAttribute : Attribute
    {
        private Lazy<MethodInfo> _base_method;
        public Type CrossBitnessType { get; private set; }

        private static MethodInfo GetMethodInfo(Type cross_bitness_type)
        {
            Func<long, int> read_memory = NtProcess.Current.ReadMemory<int>;
            return read_memory.Method.GetGenericMethodDefinition().MakeGenericMethod(cross_bitness_type);
        }

        public CrossBitnessTypeAttribute(Type cross_bitness_type)
        {
            CrossBitnessType = cross_bitness_type;
            _base_method = new Lazy<MethodInfo>(() => GetMethodInfo(cross_bitness_type));
        }

        public T ReadType<T>(NtProcess process, long base_address) where T : struct
        {
            IConvertToNative<T> converter = (IConvertToNative<T>)_base_method.Value.Invoke(process, new object[] { base_address });
            return converter.Convert();
        }

        public int GetSize()
        {
            return Marshal.SizeOf(CrossBitnessType);
        }
    }

    internal interface IConvertToNative<T> where T : struct
    {
        T Convert();
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IntPtr32 : IConvertToNative<IntPtr>
    {
        public int value;

        public IntPtr Convert()
        {
            return new IntPtr(value);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UIntPtr32 : IConvertToNative<UIntPtr>
    {
        public uint value;

        public UIntPtr Convert()
        {
            return new UIntPtr(value);
        }
    }

    internal interface IMemoryReader
    {
        byte ReadByte(IntPtr address);
        byte[] ReadBytes(IntPtr address, int length);
        short ReadInt16(IntPtr address);
        IntPtr ReadIntPtr(IntPtr address);
        int ReadInt32(IntPtr address);
        T ReadStruct<T>(IntPtr address) where T : struct;
        T[] ReadArray<T>(IntPtr address, int count) where T : struct;
        BinaryReader GetReader(IntPtr address);
        bool InProcess { get; }
    }

    internal class CurrentProcessMemoryReader : IMemoryReader
    {
        public bool InProcess => true;

        public BinaryReader GetReader(IntPtr address)
        {
            return new BinaryReader(new UnmanagedMemoryStream(new SafeBufferWrapper(address), 0, int.MaxValue));
        }

        public byte ReadByte(IntPtr address)
        {
            return Marshal.ReadByte(address);
        }

        public short ReadInt16(IntPtr address)
        {
            return Marshal.ReadInt16(address);
        }

        public int ReadInt32(IntPtr address)
        {
            return Marshal.ReadInt32(address);
        }

        public IntPtr ReadIntPtr(IntPtr address)
        {
            return Marshal.ReadIntPtr(address);
        }

        public byte[] ReadBytes(IntPtr address, int length)
        {
            byte[] ret = new byte[length];
            Marshal.Copy(address, ret, 0, length);
            return ret;
        }

        public T ReadStruct<T>(IntPtr address) where T : struct
        {
            return (T)Marshal.PtrToStructure(address, typeof(T));
        }

        public T[] ReadArray<T>(IntPtr address, int count) where T : struct
        {
            var buffer = new SafeBufferWrapper(address);
            T[] ret = new T[count];
            buffer.ReadArray(0, ret, 0, count);
            return ret;
        }
    }

    internal class ProcessMemoryStream : Stream
    {
        private readonly long _base_address;
        private readonly NtProcess _process;
        private long _offset;

        internal ProcessMemoryStream(NtProcess process, IntPtr base_address)
        {
            _process = process;
            _base_address = base_address.ToInt64();
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => _offset; set => _offset = value; }

        public override void Flush()
        {
            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var result = _process.ReadMemory(_base_address + _offset, count);
            Array.Copy(result, 0, buffer, offset, result.Length);
            _offset += result.Length;
            return result.Length;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }

    /// <summary>
    /// IMemoryReader implementation for a process.
    /// </summary>
    internal class ProcessMemoryReader : IMemoryReader
    {
        protected readonly NtProcess _process;

        internal ProcessMemoryReader(NtProcess process)
        {
            _process = process;
        }

        public bool InProcess => false;

        public BinaryReader GetReader(IntPtr address)
        {
            return new BinaryReader(new ProcessMemoryStream(_process, address));
        }

        public byte ReadByte(IntPtr address)
        {
            return _process.ReadMemory<byte>(address.ToInt64());
        }

        public byte[] ReadBytes(IntPtr address, int length)
        {
            return _process.ReadMemory(address.ToInt64(), length, true);
        }

        public short ReadInt16(IntPtr address)
        {
            return _process.ReadMemory<short>(address.ToInt64());
        }

        public int ReadInt32(IntPtr address)
        {
            return _process.ReadMemory<int>(address.ToInt64());
        }

        public virtual IntPtr ReadIntPtr(IntPtr address)
        {
            return _process.ReadMemory<IntPtr>(address.ToInt64());
        }

        public virtual T ReadStruct<T>(IntPtr address) where T : struct
        {
            return _process.ReadMemory<T>(address.ToInt64());
        }

        public virtual T[] ReadArray<T>(IntPtr address, int count) where T : struct
        {
            T[] ret = new T[count];
            int size = Marshal.SizeOf(typeof(T));
            for (int i = 0; i < count; ++i)
            {
                ret[i] = ReadStruct<T>(address + i * size);
            }
            return ret;
        }
    }

    /// <summary>
    /// IMemoryReader implementation for a process.
    /// </summary>
    internal sealed class CrossBitnessProcessMemoryReader : ProcessMemoryReader
    {
        internal CrossBitnessProcessMemoryReader(NtProcess process) : base(process)
        {
        }

        public override IntPtr ReadIntPtr(IntPtr address)
        {
            return _process.ReadMemory<IntPtr32>(address.ToInt64()).Convert();
        }

        private static CrossBitnessTypeAttribute GetCrossBitnessAttribute<T>() where T : struct
        {
            object[] attrs = typeof(T).GetCustomAttributes(typeof(CrossBitnessTypeAttribute), false);
            if (attrs.Length > 0)
            {
                return (CrossBitnessTypeAttribute)attrs[0];
            }
            return null;
        }

        public override T ReadStruct<T>(IntPtr address)
        {
            var attr = GetCrossBitnessAttribute<T>();
            if (attr == null)
            {
                return base.ReadStruct<T>(address);
            }

            return attr.ReadType<T>(_process, address.ToInt64());
        }

        public override T[] ReadArray<T>(IntPtr address, int count)
        {
            var attr = GetCrossBitnessAttribute<T>();
            if (attr == null)
            {
                return base.ReadArray<T>(address, count);
            }

            T[] ret = new T[count];
            int size = attr.GetSize();
            for (int i = 0; i < count; ++i)
            {
                ret[i] = attr.ReadType<T>(_process, address.ToInt64() + i * size);
            }
            return ret;
        }
    }
}
