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
using System.Collections.Generic;

namespace NtCoreLib.Ndr.Marshal;

#pragma warning disable 1591

/// <summary>
/// Class to delegate NDR marshal calls.
/// </summary>
public abstract class NdrMarshalBufferDelegator : INdrMarshalBuffer
{
    protected readonly INdrMarshalBuffer _buffer;

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="buffer">The buffer to delegate to.</param>
    protected NdrMarshalBufferDelegator(INdrMarshalBuffer buffer)
    {
        _buffer = buffer;
    }

    public virtual NdrDataRepresentation DataRepresentation => _buffer.DataRepresentation;

    public virtual IReadOnlyList<NdrSystemHandle> Handles => _buffer.Handles;

    public virtual byte[] ToArray()
    {
        return _buffer.ToArray();
    }

    public virtual NdrPickledType ToPickledType()
    {
        return _buffer.ToPickledType();
    }

    public virtual void WriteBasicString(string str)
    {
        _buffer.WriteBasicString(str);
    }

    public virtual void WriteByte(byte b)
    {
        _buffer.WriteByte(b);
    }

    public virtual void WriteByte(byte? b)
    {
        _buffer.WriteByte(b);
    }

    public virtual void WriteBytes(byte[] array)
    {
        _buffer.WriteBytes(array);
    }

    public virtual void WriteChar(char c)
    {
        _buffer.WriteChar(c);
    }

    public virtual void WriteChar(char? c)
    {
        _buffer.WriteChar(c);
    }

    public virtual void WriteChars(char[] chars)
    {
        _buffer.WriteChars(chars);
    }

    public virtual void WriteConformantArray<T>(T[] array, long conformance) where T : struct
    {
        _buffer.WriteConformantArray(array, conformance);
    }

    public virtual void WriteConformantArrayCallback<T>(T[] array, Action<T> writer, long conformance)
    {
        _buffer.WriteConformantArrayCallback(array, writer, conformance);
    }

    public virtual void WriteConformantByteArray(byte[] array, long conformance)
    {
        _buffer.WriteConformantByteArray(array, conformance);
    }

    public virtual void WriteConformantCharArray(char[] array, long conformance)
    {
        _buffer.WriteConformantCharArray(array, conformance);
    }

    public virtual void WriteConformantPrimitiveArray<T>(T[] array, long conformance) where T : struct
    {
        _buffer.WriteConformantPrimitiveArray(array, conformance);
    }

    public virtual void WriteConformantStringArray(string[] array, Action<string> writer, long conformance)
    {
        _buffer.WriteConformantStringArray(array, writer, conformance);
    }

    public virtual void WriteConformantStructArray<T>(T[] array, long conformance) where T : struct, INdrStructure
    {
        _buffer.WriteConformantStructArray(array, conformance);
    }

    public virtual void WriteConformantStructPointerArray<T>(T?[] array, long conformance) where T : struct, INdrStructure
    {
        _buffer.WriteConformantStructPointerArray(array, conformance);
    }

    public virtual void WriteConformantVaryingAnsiString(string str, long conformance)
    {
        _buffer.WriteConformantVaryingAnsiString(str, conformance);
    }

    public virtual void WriteConformantVaryingArray<T>(T[] array, long conformance, long variance) where T : struct
    {
        _buffer.WriteConformantVaryingArray(array, conformance, variance);
    }

    public virtual void WriteConformantVaryingArrayCallback<T>(T[] array, Action<T> writer, long conformance, long variance)
    {
        _buffer.WriteConformantVaryingArrayCallback(array, writer, conformance, variance);
    }

    public virtual void WriteConformantVaryingByteArray(byte[] array, long conformance, long variance)
    {
        _buffer.WriteConformantVaryingByteArray(array, conformance, variance);
    }

    public virtual void WriteConformantVaryingCharArray(char[] array, long conformance, long variance)
    {
        _buffer.WriteConformantVaryingCharArray(array, conformance, variance);
    }

    public virtual void WriteConformantVaryingPrimitiveArray<T>(T[] array, long conformance, long variance) where T : struct
    {
        _buffer.WriteConformantVaryingPrimitiveArray(array, conformance, variance);
    }

    public virtual void WriteConformantVaryingString(string str, long conformance)
    {
        _buffer.WriteConformantVaryingString(str, conformance);
    }

    public virtual void WriteConformantVaryingStringArray(string[] array, Action<string> writer, long conformance, long variance)
    {
        _buffer.WriteConformantVaryingStringArray(array, writer, conformance, variance);
    }

    public virtual void WriteConformantVaryingStructArray<T>(T[] array, long conformance, long variance) where T : struct, INdrStructure
    {
        _buffer.WriteConformantVaryingStructArray(array, conformance, variance);
    }

    public virtual void WriteConformantVaryingStructPointerArray<T>(T?[] array, long conformance, long variance) where T : struct, INdrStructure
    {
        _buffer.WriteConformantVaryingStructPointerArray(array, conformance, variance);
    }

    public virtual void WriteContextHandle(NdrContextHandle handle)
    {
        _buffer.WriteContextHandle(handle);
    }

    public virtual void WriteContextHandle(NdrTypeStrictContextHandle handle)
    {
        _buffer.WriteContextHandle(handle);
    }

    public virtual void WriteDouble(double d)
    {
        _buffer.WriteDouble(d);
    }

    public virtual void WriteDouble(double? d)
    {
        _buffer.WriteDouble(d);
    }

    public virtual void WriteEmbeddedPointer<T, U, V>(NdrEmbeddedPointer<T> pointer, Action<T, U, V> writer, U arg, V arg2)
    {
        _buffer.WriteEmbeddedPointer(pointer, writer, arg, arg2);
    }

    public virtual void WriteEmbeddedPointer<T, U>(NdrEmbeddedPointer<T> pointer, Action<T, U> writer, U arg)
    {
        _buffer.WriteEmbeddedPointer(pointer, writer, arg);
    }

    public virtual void WriteEmbeddedPointer<T>(NdrEmbeddedPointer<T> pointer, Action<T> writer)
    {
        _buffer.WriteEmbeddedPointer(pointer, writer);
    }

    public virtual void WriteEmpty(NdrEmpty empty)
    {
        _buffer.WriteEmpty(empty);
    }

    public virtual void WriteEnum16(NdrEnum16 e)
    {
        _buffer.WriteEnum16(e);
    }

    public virtual void WriteEnum16(NdrEnum16? p)
    {
        _buffer.WriteEnum16(p);
    }

    public virtual void WriteFixedAnsiString(string str, int fixed_count)
    {
        _buffer.WriteFixedAnsiString(str, fixed_count);
    }

    public virtual void WriteFixedByteArray(byte[] array, int actual_count)
    {
        _buffer.WriteFixedByteArray(array, actual_count);
    }

    public virtual void WriteFixedChars(char[] chars, int fixed_count)
    {
        _buffer.WriteFixedChars(chars, fixed_count);
    }

    public virtual void WriteFixedPrimitiveArray<T>(T[] array, int fixed_count) where T : struct
    {
        _buffer.WriteFixedPrimitiveArray(array, fixed_count);
    }

    public virtual void WriteFixedString(string str, int fixed_count)
    {
        _buffer.WriteFixedString(str, fixed_count);
    }

    public virtual void WriteFixedStructArray<T>(T[] arr, int actual_count) where T : INdrStructure, new()
    {
        _buffer.WriteFixedStructArray(arr, actual_count);
    }

    public virtual void WriteFloat(float f)
    {
        _buffer.WriteFloat(f);
    }

    public virtual void WriteFloat(float? f)
    {
        _buffer.WriteFloat(f);
    }

    public virtual void WriteGuid(Guid guid)
    {
        _buffer.WriteGuid(guid);
    }

    public virtual void WriteGuid(Guid? guid)
    {
        _buffer.WriteGuid(guid);
    }

    public virtual void WriteHString(string str)
    {
        _buffer.WriteHString(str);
    }

    public virtual void WriteIgnorePointer(IntPtr value)
    {
        _buffer.WriteIgnorePointer(value);
    }

    public virtual void WriteInt16(short s)
    {
        _buffer.WriteInt16(s);
    }

    public virtual void WriteInt16(short? s)
    {
        _buffer.WriteInt16(s);
    }

    public virtual void WriteInt32(int i)
    {
        _buffer.WriteInt32(i);
    }

    public virtual void WriteInt32(int? i)
    {
        _buffer.WriteInt32(i);
    }

    public virtual void WriteInt3264(NdrInt3264 p)
    {
        _buffer.WriteInt3264(p);
    }

    public virtual void WriteInt3264(NdrInt3264? p)
    {
        _buffer.WriteInt3264(p);
    }

    public virtual void WriteInt64(long l)
    {
        _buffer.WriteInt64(l);
    }

    public virtual void WriteInt64(long? l)
    {
        _buffer.WriteInt64(l);
    }

    public virtual void WriteInterfacePointer(NdrInterfacePointer intf)
    {
        _buffer.WriteInterfacePointer(intf);
    }

    public virtual void WritePipe<T>(NdrPipe<T> pipe) where T : struct
    {
        _buffer.WritePipe(pipe);
    }

    public virtual void WritePipeArray<T>(T[] pipe_array) where T : struct
    {
        _buffer.WritePipeArray(pipe_array);
    }

    public virtual void WriteReferent<T, U, V>(T obj, Action<T, U, V> writer, U arg, V arg2) where T : class
    {
        _buffer.WriteReferent<T, U, V>(obj, writer, arg, arg2);
    }

    public virtual void WriteReferent<T, U, V>(T? obj, Action<T, U, V> writer, U arg, V arg2) where T : struct
    {
        _buffer.WriteReferent(obj, writer, arg, arg2);
    }

    public virtual void WriteReferent<T, U>(T obj, Action<T, U> writer, U arg) where T : class
    {
        _buffer.WriteReferent<T, U>(obj, writer, arg);
    }

    public virtual void WriteReferent<T, U>(T? obj, Action<T, U> writer, U arg) where T : struct
    {
        _buffer.WriteReferent(obj, writer, arg);
    }

    public virtual void WriteReferent<T>(T obj, Action<T> writer) where T : class
    {
        _buffer.WriteReferent<T>(obj, writer);
    }

    public virtual void WriteReferent<T>(T? obj, Action<T> writer) where T : struct
    {
        _buffer.WriteReferent(obj, writer);
    }

    public virtual void WriteSByte(sbyte b)
    {
        _buffer.WriteSByte(b);
    }

    public virtual void WriteSByte(sbyte? b)
    {
        _buffer.WriteSByte(b);
    }

    public virtual void WriteStruct(INdrStructure structure)
    {
        _buffer.WriteStruct(structure);
    }

    public virtual void WriteStruct<T>(T structure) where T : struct, INdrStructure
    {
        _buffer.WriteStruct(structure);
    }

    public virtual void WriteStruct<T>(T? structure) where T : struct, INdrStructure
    {
        _buffer.WriteStruct(structure);
    }

    public virtual void WriteSystemHandle<T>(T handle, uint desired_access = 0) where T : NtObject
    {
        _buffer.WriteSystemHandle<T>(handle, desired_access);
    }

    public virtual void WriteTerminatedAnsiString(string str)
    {
        _buffer.WriteTerminatedAnsiString(str);
    }

    public virtual void WriteTerminatedString(string str)
    {
        _buffer.WriteTerminatedString(str);
    }

    public virtual void WriteUInt16(ushort s)
    {
        _buffer.WriteUInt16(s);
    }

    public virtual void WriteUInt16(ushort? s)
    {
        _buffer.WriteUInt16(s);
    }

    public virtual void WriteUInt32(uint i)
    {
        _buffer.WriteUInt32(i);
    }

    public virtual void WriteUInt32(uint? i)
    {
        _buffer.WriteUInt32(i);
    }

    public virtual void WriteUInt3264(NdrUInt3264 p)
    {
        _buffer.WriteUInt3264(p);
    }

    public virtual void WriteUInt3264(NdrUInt3264? p)
    {
        _buffer.WriteUInt3264(p);
    }

    public virtual void WriteUInt64(ulong l)
    {
        _buffer.WriteUInt64(l);
    }

    public virtual void WriteUInt64(ulong? l)
    {
        _buffer.WriteUInt64(l);
    }

    public virtual void WriteUnion(INdrNonEncapsulatedUnion union, long selector)
    {
        _buffer.WriteUnion(union, selector);
    }

    public virtual void WriteUnion<T>(T union, long selector) where T : struct, INdrNonEncapsulatedUnion
    {
        _buffer.WriteUnion(union, selector);
    }

    public virtual void WriteUnion<T>(T? union, long selector) where T : struct, INdrNonEncapsulatedUnion
    {
        _buffer.WriteUnion(union, selector);
    }

    public virtual void WriteUnsupported(NdrUnsupported type, string name)
    {
        _buffer.WriteUnsupported(type, name);
    }

    public virtual void WriteVaryingAnsiString(string str)
    {
        _buffer.WriteVaryingAnsiString(str);
    }

    public virtual void WriteVaryingArray<T>(T[] array, long variance) where T : struct
    {
        _buffer.WriteVaryingArray(array, variance);
    }

    public virtual void WriteVaryingArrayCallback<T>(T[] array, Action<T> writer, long variance)
    {
        _buffer.WriteVaryingArrayCallback(array, writer, variance);
    }

    public virtual void WriteVaryingByteArray(byte[] array, long variance)
    {
        _buffer.WriteVaryingByteArray(array, variance);
    }

    public virtual void WriteVaryingCharArray(char[] array, long variance)
    {
        _buffer.WriteVaryingCharArray(array, variance);
    }

    public virtual void WriteVaryingPrimitiveArray<T>(T[] array, long variance) where T : struct
    {
        _buffer.WriteVaryingPrimitiveArray(array, variance);
    }

    public virtual void WriteVaryingString(string str)
    {
        _buffer.WriteVaryingString(str);
    }

    public virtual void WriteVaryingStringArray(string[] array, Action<string> writer, long variance)
    {
        _buffer.WriteVaryingStringArray(array, writer, variance);
    }

    public virtual void WriteVaryingStructArray<T>(T[] array, long variance) where T : struct, INdrStructure
    {
        _buffer.WriteVaryingStructArray(array, variance);
    }

    public virtual void WriteVaryingStructPointerArray<T>(T?[] array, long variance) where T : struct, INdrStructure
    {
        _buffer.WriteVaryingStructPointerArray(array, variance);
    }
}