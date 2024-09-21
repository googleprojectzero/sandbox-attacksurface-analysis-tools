//  Copyright 2023 Google LLC. All Rights Reserved.
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
//
//  Note this is relicensed from OleViewDotNet by the author.

using NtCoreLib.Native.SafeBuffers;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Win32.SideBySide.Parser;

internal static class ActivationContextParserUtils
{
    public static string ReadString(this SafeBufferGeneric buffer, int offset, int length)
    {
        if (length == 0)
            return string.Empty;
        return buffer.ReadUnicodeString((ulong)offset, length / 2).TrimEnd('\0');
    }

    public static T ReadStruct<T>(this SafeBufferGeneric buffer, int offset) where T : struct
    {
        return buffer.Read<T>((ulong)offset);
    }

    public static IReadOnlyList<T> ToReadOnlyList<T>(this IEnumerable<T> enumerable)
    {
        return enumerable.ToList().AsReadOnly();
    }
}
