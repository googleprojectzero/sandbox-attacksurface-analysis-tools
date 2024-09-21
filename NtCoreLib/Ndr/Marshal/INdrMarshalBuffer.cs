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
/// An interface to marshal NDR data.
/// </summary>
/// <remarks>This interface is primarily for internal use only.</remarks>
public interface INdrMarshalBuffer
{
    NdrDataRepresentation DataRepresentation { get; }
    IReadOnlyList<NdrSystemHandle> Handles { get; }

    byte[] ToArray();
    NdrPickledType ToPickledType();
    void WriteBasicString(string str);
    void WriteByte(byte b);
    void WriteByte(byte? b);
    void WriteBytes(byte[] array);
    void WriteChar(char c);
    void WriteChar(char? c);
    void WriteChars(char[] chars);
    void WriteConformantArray<T>(T[] array, long conformance) where T : struct;
    void WriteConformantArrayCallback<T>(T[] array, Action<T> writer, long conformance);
    void WriteConformantByteArray(byte[] array, long conformance);
    void WriteConformantCharArray(char[] array, long conformance);
    void WriteConformantPrimitiveArray<T>(T[] array, long conformance) where T : struct;
    void WriteConformantStringArray(string[] array, Action<string> writer, long conformance);
    void WriteConformantStructArray<T>(T[] array, long conformance) where T : struct, INdrStructure;
    void WriteConformantStructPointerArray<T>(T?[] array, long conformance) where T : struct, INdrStructure;
    void WriteConformantVaryingAnsiString(string str, long conformance);
    void WriteConformantVaryingArray<T>(T[] array, long conformance, long variance) where T : struct;
    void WriteConformantVaryingArrayCallback<T>(T[] array, Action<T> writer, long conformance, long variance);
    void WriteConformantVaryingByteArray(byte[] array, long conformance, long variance);
    void WriteConformantVaryingCharArray(char[] array, long conformance, long variance);
    void WriteConformantVaryingPrimitiveArray<T>(T[] array, long conformance, long variance) where T : struct;
    void WriteConformantVaryingString(string str, long conformance);
    void WriteConformantVaryingStringArray(string[] array, Action<string> writer, long conformance, long variance);
    void WriteConformantVaryingStructArray<T>(T[] array, long conformance, long variance) where T : struct, INdrStructure;
    void WriteConformantVaryingStructPointerArray<T>(T?[] array, long conformance, long variance) where T : struct, INdrStructure;
    void WriteContextHandle(NdrContextHandle handle);
    void WriteContextHandle(NdrTypeStrictContextHandle handle);
    void WriteDouble(double d);
    void WriteDouble(double? d);
    void WriteEmbeddedPointer<T, U, V>(NdrEmbeddedPointer<T> pointer, Action<T, U, V> writer, U arg, V arg2);
    void WriteEmbeddedPointer<T, U>(NdrEmbeddedPointer<T> pointer, Action<T, U> writer, U arg);
    void WriteEmbeddedPointer<T>(NdrEmbeddedPointer<T> pointer, Action<T> writer);
    void WriteEmpty(NdrEmpty empty);
    void WriteEnum16(NdrEnum16 e);
    void WriteEnum16(NdrEnum16? p);
    void WriteFixedAnsiString(string str, int fixed_count);
    void WriteFixedByteArray(byte[] array, int actual_count);
    void WriteFixedChars(char[] chars, int fixed_count);
    void WriteFixedPrimitiveArray<T>(T[] array, int fixed_count) where T : struct;
    void WriteFixedString(string str, int fixed_count);
    void WriteFixedStructArray<T>(T[] arr, int actual_count) where T : INdrStructure, new();
    void WriteFloat(float f);
    void WriteFloat(float? f);
    void WriteGuid(Guid guid);
    void WriteGuid(Guid? guid);
    void WriteHString(string str);
    void WriteIgnorePointer(IntPtr value);
    void WriteInt16(short s);
    void WriteInt16(short? s);
    void WriteInt32(int i);
    void WriteInt32(int? i);
    void WriteInt3264(NdrInt3264 p);
    void WriteInt3264(NdrInt3264? p);
    void WriteInt64(long l);
    void WriteInt64(long? l);
    void WriteInterfacePointer(NdrInterfacePointer intf);
    void WritePipe<T>(NdrPipe<T> pipe) where T : struct;
    void WritePipeArray<T>(T[] pipe_array) where T : struct;
    void WriteReferent<T, U, V>(T obj, Action<T, U, V> writer, U arg, V arg2) where T : class;
    void WriteReferent<T, U, V>(T? obj, Action<T, U, V> writer, U arg, V arg2) where T : struct;
    void WriteReferent<T, U>(T obj, Action<T, U> writer, U arg) where T : class;
    void WriteReferent<T, U>(T? obj, Action<T, U> writer, U arg) where T : struct;
    void WriteReferent<T>(T obj, Action<T> writer) where T : class;
    void WriteReferent<T>(T? obj, Action<T> writer) where T : struct;
    void WriteSByte(sbyte b);
    void WriteSByte(sbyte? b);
    void WriteStruct(INdrStructure structure);
    void WriteStruct<T>(T structure) where T : struct, INdrStructure;
    void WriteStruct<T>(T? structure) where T : struct, INdrStructure;
    void WriteSystemHandle<T>(T handle, uint desired_access = 0) where T : NtObject;
    void WriteTerminatedAnsiString(string str);
    void WriteTerminatedString(string str);
    void WriteUInt16(ushort s);
    void WriteUInt16(ushort? s);
    void WriteUInt32(uint i);
    void WriteUInt32(uint? i);
    void WriteUInt3264(NdrUInt3264 p);
    void WriteUInt3264(NdrUInt3264? p);
    void WriteUInt64(ulong l);
    void WriteUInt64(ulong? l);
    void WriteUnion(INdrNonEncapsulatedUnion union, long selector);
    void WriteUnion<T>(T union, long selector) where T : struct, INdrNonEncapsulatedUnion;
    void WriteUnion<T>(T? union, long selector) where T : struct, INdrNonEncapsulatedUnion;
    void WriteUnsupported(NdrUnsupported type, string name);
    void WriteVaryingAnsiString(string str);
    void WriteVaryingArray<T>(T[] array, long variance) where T : struct;
    void WriteVaryingArrayCallback<T>(T[] array, Action<T> writer, long variance);
    void WriteVaryingByteArray(byte[] array, long variance);
    void WriteVaryingCharArray(char[] array, long variance);
    void WriteVaryingPrimitiveArray<T>(T[] array, long variance) where T : struct;
    void WriteVaryingString(string str);
    void WriteVaryingStringArray(string[] array, Action<string> writer, long variance);
    void WriteVaryingStructArray<T>(T[] array, long variance) where T : struct, INdrStructure;
    void WriteVaryingStructPointerArray<T>(T?[] array, long variance) where T : struct, INdrStructure;
}
