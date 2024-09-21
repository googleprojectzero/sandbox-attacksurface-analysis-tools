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

namespace NtCoreLib.Ndr.Marshal;

#pragma warning disable 1591

/// <summary>
/// Class to delegate NDR unmarshal calls.
/// </summary>
public abstract class NdrUnmarshalBufferDelegator : INdrUnmarshalBuffer
{
    protected readonly INdrUnmarshalBuffer _buffer;

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="buffer">The buffer to delegate to.</param>
    protected NdrUnmarshalBufferDelegator(INdrUnmarshalBuffer buffer)
    {
        _buffer = buffer;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="type">The pickled type.</param>
    /// <remarks>Note, this will only unmarshal the first type.</remarks>
    protected NdrUnmarshalBufferDelegator(NdrPickledType type) 
        : this(type.GetUnmarshalBuffer(0))
    {
    }

    public virtual void Dispose()
    {
        _buffer.Dispose();
    }

    public virtual string ReadBasicString()
    {
        return _buffer.ReadBasicString();
    }

    public virtual byte ReadByte()
    {
        return _buffer.ReadByte();
    }

    public virtual char ReadChar()
    {
        return _buffer.ReadChar();
    }

    public virtual T[] ReadConformantArray<T>() where T : struct
    {
        return _buffer.ReadConformantArray<T>();
    }

    public virtual T[] ReadConformantArrayCallback<T>(Func<T> reader)
    {
        return _buffer.ReadConformantArrayCallback(reader);
    }

    public virtual byte[] ReadConformantByteArray()
    {
        return _buffer.ReadConformantByteArray();
    }

    public virtual char[] ReadConformantCharArray()
    {
        return _buffer.ReadConformantCharArray();
    }

    public virtual T[] ReadConformantPrimitiveArray<T>() where T : struct
    {
        return _buffer.ReadConformantPrimitiveArray<T>();
    }

    public virtual string[] ReadConformantStringArray(Func<string> reader)
    {
        return _buffer.ReadConformantStringArray(reader);
    }

    public virtual T[] ReadConformantStructArray<T>() where T : INdrStructure, new()
    {
        return _buffer.ReadConformantStructArray<T>();
    }

    public virtual T?[] ReadConformantStructPointerArray<T>(bool full_pointer) where T : struct, INdrStructure
    {
        return _buffer.ReadConformantStructPointerArray<T>(full_pointer);
    }

    public virtual string ReadConformantVaryingAnsiString()
    {
        return _buffer.ReadConformantVaryingAnsiString();
    }

    public virtual T[] ReadConformantVaryingArray<T>() where T : struct
    {
        return _buffer.ReadConformantVaryingArray<T>();
    }

    public virtual T[] ReadConformantVaryingArrayCallback<T>(Func<T> reader)
    {
        return _buffer.ReadConformantVaryingArrayCallback(reader);
    }

    public virtual byte[] ReadConformantVaryingByteArray()
    {
        return _buffer.ReadConformantVaryingByteArray();
    }

    public virtual char[] ReadConformantVaryingCharArray()
    {
        return _buffer.ReadConformantVaryingCharArray();
    }

    public virtual T[] ReadConformantVaryingPrimitiveArray<T>() where T : struct
    {
        return _buffer.ReadConformantVaryingPrimitiveArray<T>();
    }

    public virtual string ReadConformantVaryingString()
    {
        return _buffer.ReadConformantVaryingString();
    }

    public virtual string[] ReadConformantVaryingStringArray(Func<string> reader)
    {
        return _buffer.ReadConformantVaryingStringArray(reader);
    }

    public virtual T[] ReadConformantVaryingStructArray<T>() where T : INdrStructure, new()
    {
        return _buffer.ReadConformantVaryingStructArray<T>();
    }

    public virtual T?[] ReadConformantVaryingStructPointerArray<T>(bool full_pointer) where T : struct, INdrStructure
    {
        return _buffer.ReadConformantVaryingStructPointerArray<T>(full_pointer);
    }

    public virtual NdrContextHandle ReadContextHandle()
    {
        return _buffer.ReadContextHandle();
    }

    public virtual T ReadContextHandle<T>() where T : NdrTypeStrictContextHandle, new()
    {
        return _buffer.ReadContextHandle<T>();
    }

    public virtual double ReadDouble()
    {
        return _buffer.ReadDouble();
    }

    public virtual NdrEmbeddedPointer<T> ReadEmbeddedPointer<T, U, V>(Func<U, V, T> unmarshal_func, bool full_pointer, U arg, V arg2)
    {
        return _buffer.ReadEmbeddedPointer(unmarshal_func, full_pointer, arg, arg2);
    }

    public virtual NdrEmbeddedPointer<T> ReadEmbeddedPointer<T, U>(Func<U, T> unmarshal_func, bool full_pointer, U arg)
    {
        return _buffer.ReadEmbeddedPointer(unmarshal_func, full_pointer, arg);
    }

    public virtual NdrEmbeddedPointer<T> ReadEmbeddedPointer<T>(Func<T> unmarshal_func, bool full_pointer)
    {
        return _buffer.ReadEmbeddedPointer(unmarshal_func, full_pointer);
    }

    public virtual NdrEmpty ReadEmpty()
    {
        return _buffer.ReadEmpty();
    }

    public virtual NdrEnum16 ReadEnum16()
    {
        return _buffer.ReadEnum16();
    }

    public virtual string ReadFixedAnsiString(int count)
    {
        return _buffer.ReadFixedAnsiString(count);
    }

    public virtual T[] ReadFixedArray<T>(Func<T> reader, int actual_count)
    {
        return _buffer.ReadFixedArray(reader, actual_count);
    }

    public virtual byte[] ReadRemaining()
    {
        return _buffer.ReadRemaining();
    }

    public virtual byte[] ReadFixedByteArray(int count)
    {
        return _buffer.ReadFixedByteArray(count);
    }

    public virtual char[] ReadFixedCharArray(int count)
    {
        return _buffer.ReadFixedCharArray(count);
    }

    public virtual T[] ReadFixedPrimitiveArray<T>(int actual_count) where T : struct
    {
        return _buffer.ReadFixedPrimitiveArray<T>(actual_count);
    }

    public virtual string ReadFixedString(int count)
    {
        return _buffer.ReadFixedString(count);
    }

    public virtual T[] ReadFixedStructArray<T>(int actual_count) where T : INdrStructure, new()
    {
        return _buffer.ReadFixedStructArray<T>(actual_count);
    }

    public virtual float ReadFloat()
    {
        return _buffer.ReadFloat();
    }

    public virtual Guid ReadGuid()
    {
        return _buffer.ReadGuid();
    }

    public virtual string ReadHString()
    {
        return _buffer.ReadHString();
    }

    public virtual IntPtr ReadIgnorePointer()
    {
        return _buffer.ReadIgnorePointer();
    }

    public virtual short ReadInt16()
    {
        return _buffer.ReadInt16();
    }

    public virtual int ReadInt32()
    {
        return _buffer.ReadInt32();
    }

    public virtual NdrInt3264 ReadInt3264()
    {
        return _buffer.ReadInt3264();
    }

    public virtual long ReadInt64()
    {
        return _buffer.ReadInt64();
    }

    public virtual NdrInterfacePointer ReadInterfacePointer()
    {
        return _buffer.ReadInterfacePointer();
    }

    public virtual NdrPipe<T> ReadPipe<T>() where T : struct
    {
        return _buffer.ReadPipe<T>();
    }

    public virtual T[] ReadPipeArray<T>() where T : struct
    {
        return _buffer.ReadPipeArray<T>();
    }

    public virtual T ReadReferent<T, U, V>(Func<U, V, T> unmarshal_func, bool full_pointer, U arg1, V arg2) where T : class
    {
        return _buffer.ReadReferent(unmarshal_func, full_pointer, arg1, arg2);
    }

    public virtual T ReadReferent<T, U>(Func<U, T> unmarshal_func, bool full_pointer, U arg) where T : class
    {
        return _buffer.ReadReferent(unmarshal_func, full_pointer, arg);
    }

    public virtual T ReadReferent<T>(Func<T> unmarshal_func, bool full_pointer) where T : class
    {
        return _buffer.ReadReferent(unmarshal_func, full_pointer);
    }

    public virtual T? ReadReferentValue<T, U, V>(Func<U, V, T> unmarshal_func, bool full_pointer, U arg1, V arg2) where T : struct
    {
        return _buffer.ReadReferentValue(unmarshal_func, full_pointer, arg1, arg2);
    }

    public virtual T? ReadReferentValue<T, U>(Func<U, T> unmarshal_func, bool full_pointer, U arg) where T : struct
    {
        return _buffer.ReadReferentValue(unmarshal_func, full_pointer, arg);
    }

    public virtual T? ReadReferentValue<T>(Func<T> unmarshal_func, bool full_pointer) where T : struct
    {
        return _buffer.ReadReferentValue(unmarshal_func, full_pointer);
    }

    public virtual sbyte ReadSByte()
    {
        return _buffer.ReadSByte();
    }

    public virtual T ReadStruct<T>() where T : INdrStructure, new()
    {
        return _buffer.ReadStruct<T>();
    }

    public virtual T ReadSystemHandle<T>() where T : NtObject
    {
        return _buffer.ReadSystemHandle<T>();
    }

    public virtual ushort ReadUInt16()
    {
        return _buffer.ReadUInt16();
    }

    public virtual uint ReadUInt32()
    {
        return _buffer.ReadUInt32();
    }

    public virtual NdrUInt3264 ReadUInt3264()
    {
        return _buffer.ReadUInt3264();
    }

    public virtual ulong ReadUInt64()
    {
        return _buffer.ReadUInt64();
    }

    public virtual NdrUnsupported ReadUnsupported(string name)
    {
        return _buffer.ReadUnsupported(name);
    }

    public virtual string ReadVaryingAnsiString()
    {
        return _buffer.ReadVaryingAnsiString();
    }

    public virtual T[] ReadVaryingArray<T>() where T : struct
    {
        return _buffer.ReadVaryingArray<T>();
    }

    public virtual T[] ReadVaryingArrayCallback<T>(Func<T> reader)
    {
        return _buffer.ReadVaryingArrayCallback(reader);
    }

    public virtual byte[] ReadVaryingByteArray()
    {
        return _buffer.ReadVaryingByteArray();
    }

    public virtual char[] ReadVaryingCharArray()
    {
        return _buffer.ReadVaryingCharArray();
    }

    public virtual T[] ReadVaryingPrimitiveArray<T>() where T : struct
    {
        return _buffer.ReadVaryingPrimitiveArray<T>();
    }

    public virtual string ReadVaryingString()
    {
        return _buffer.ReadVaryingString();
    }

    public virtual string[] ReadVaryingStringArray(Func<string> reader)
    {
        return _buffer.ReadVaryingStringArray(reader);
    }

    public virtual T[] ReadVaryingStructArray<T>() where T : INdrStructure, new()
    {
        return _buffer.ReadVaryingStructArray<T>();
    }

    public virtual T?[] ReadVaryingStructPointerArray<T>(bool full_pointer) where T : struct, INdrStructure
    {
        return _buffer.ReadVaryingStructPointerArray<T>(full_pointer);
    }

    public byte[] ToArray()
    {
        return _buffer.ToArray();
    }
}