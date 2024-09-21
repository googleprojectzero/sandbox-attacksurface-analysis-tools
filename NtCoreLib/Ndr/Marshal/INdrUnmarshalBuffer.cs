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
/// A buffer to unmarshal NDR data from.
/// </summary>
/// <remarks>This class is primarily for internal use only.</remarks>
public interface INdrUnmarshalBuffer : IDisposable
{
    string ReadBasicString();
    byte ReadByte();
    char ReadChar();
    T[] ReadConformantArray<T>() where T : struct;
    T[] ReadConformantArrayCallback<T>(Func<T> reader);
    byte[] ReadConformantByteArray();
    char[] ReadConformantCharArray();
    T[] ReadConformantPrimitiveArray<T>() where T : struct;
    string[] ReadConformantStringArray(Func<string> reader);
    T[] ReadConformantStructArray<T>() where T : INdrStructure, new();
    T?[] ReadConformantStructPointerArray<T>(bool full_pointer) where T : struct, INdrStructure;
    string ReadConformantVaryingAnsiString();
    T[] ReadConformantVaryingArray<T>() where T : struct;
    T[] ReadConformantVaryingArrayCallback<T>(Func<T> reader);
    byte[] ReadConformantVaryingByteArray();
    char[] ReadConformantVaryingCharArray();
    T[] ReadConformantVaryingPrimitiveArray<T>() where T : struct;
    string ReadConformantVaryingString();
    string[] ReadConformantVaryingStringArray(Func<string> reader);
    T[] ReadConformantVaryingStructArray<T>() where T : INdrStructure, new();
    T?[] ReadConformantVaryingStructPointerArray<T>(bool full_pointer) where T : struct, INdrStructure;
    NdrContextHandle ReadContextHandle();
    T ReadContextHandle<T>() where T : NdrTypeStrictContextHandle, new();
    double ReadDouble();
    NdrEmbeddedPointer<T> ReadEmbeddedPointer<T, U, V>(Func<U, V, T> unmarshal_func, bool full_pointer, U arg, V arg2);
    NdrEmbeddedPointer<T> ReadEmbeddedPointer<T, U>(Func<U, T> unmarshal_func, bool full_pointer, U arg);
    NdrEmbeddedPointer<T> ReadEmbeddedPointer<T>(Func<T> unmarshal_func, bool full_pointer);
    NdrEmpty ReadEmpty();
    NdrEnum16 ReadEnum16();
    string ReadFixedAnsiString(int count);
    T[] ReadFixedArray<T>(Func<T> reader, int actual_count);
    byte[] ReadRemaining();
    byte[] ReadFixedByteArray(int count);
    char[] ReadFixedCharArray(int count);
    T[] ReadFixedPrimitiveArray<T>(int actual_count) where T : struct;
    string ReadFixedString(int count);
    T[] ReadFixedStructArray<T>(int actual_count) where T : INdrStructure, new();
    float ReadFloat();
    Guid ReadGuid();
    string ReadHString();
    IntPtr ReadIgnorePointer();
    short ReadInt16();
    int ReadInt32();
    NdrInt3264 ReadInt3264();
    long ReadInt64();
    NdrInterfacePointer ReadInterfacePointer();
    NdrPipe<T> ReadPipe<T>() where T : struct;
    T[] ReadPipeArray<T>() where T : struct;
    T ReadReferent<T, U, V>(Func<U, V, T> unmarshal_func, bool full_pointer, U arg1, V arg2) where T : class;
    T ReadReferent<T, U>(Func<U, T> unmarshal_func, bool full_pointer, U arg) where T : class;
    T ReadReferent<T>(Func<T> unmarshal_func, bool full_pointer) where T : class;
    T? ReadReferentValue<T, U, V>(Func<U, V, T> unmarshal_func, bool full_pointer, U arg1, V arg2) where T : struct;
    T? ReadReferentValue<T, U>(Func<U, T> unmarshal_func, bool full_pointer, U arg) where T : struct;
    T? ReadReferentValue<T>(Func<T> unmarshal_func, bool full_pointer) where T : struct;
    sbyte ReadSByte();
    T ReadStruct<T>() where T : INdrStructure, new();
    T ReadSystemHandle<T>() where T : NtObject;
    ushort ReadUInt16();
    uint ReadUInt32();
    NdrUInt3264 ReadUInt3264();
    ulong ReadUInt64();
    NdrUnsupported ReadUnsupported(string name);
    string ReadVaryingAnsiString();
    T[] ReadVaryingArray<T>() where T : struct;
    T[] ReadVaryingArrayCallback<T>(Func<T> reader);
    byte[] ReadVaryingByteArray();
    char[] ReadVaryingCharArray();
    T[] ReadVaryingPrimitiveArray<T>() where T : struct;
    string ReadVaryingString();
    string[] ReadVaryingStringArray(Func<string> reader);
    T[] ReadVaryingStructArray<T>() where T : INdrStructure, new();
    T?[] ReadVaryingStructPointerArray<T>(bool full_pointer) where T : struct, INdrStructure;
    byte[] ToArray();
}