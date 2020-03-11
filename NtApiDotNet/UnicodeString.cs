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

using NtApiDotNet.Utilities.Memory;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    /// <summary>
    /// Standard UNICODE_STRING class
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class UnicodeString
    {
        ushort Length;
        ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        string Buffer;

        public UnicodeString(string str)
        {
            Length = (ushort)(str.Length * 2);
            MaximumLength = (ushort)((str.Length + 1) * 2);
            Buffer = str;
        }

        public UnicodeString()
        {
            Length = 0;
            MaximumLength = 0;
            Buffer = null;
        }

        public override string ToString()
        {
            return Buffer;
        }
    }

    /// <summary>
    /// Standard ANSI_STRING class
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public sealed class AnsiString
    {
        private readonly ushort Length;
        private readonly ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPStr)]
        private readonly string Buffer;

        public AnsiString(string str)
        {
            Length = (ushort)str.Length;
            MaximumLength = (ushort)(str.Length + 1);
            Buffer = str;
        }

        public AnsiString()
        {
            Length = 0;
            MaximumLength = 0;
            Buffer = null;
        }

        public override string ToString()
        {
            return Buffer;
        }
    }

    /// <summary>
    /// This class is used when the UNICODE_STRING is an output parameter.
    /// The allocatation of the buffer is handled elsewhere.
    /// </summary>
    [StructLayout(LayoutKind.Sequential), CrossBitnessType(typeof(UnicodeStringOut32))]
    public struct UnicodeStringOut
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
        public override string ToString()
        {
            if (Buffer != IntPtr.Zero)
                return Marshal.PtrToStringUni(Buffer, Length / 2);
            return string.Empty;
        }

        internal string ToString(NtProcess process)
        {
            if (Length == 0 || Buffer == IntPtr.Zero)
            {
                return string.Empty;
            }

            return new string(process.ReadMemoryArray<char>(Buffer.ToInt64(),
                Length / 2));
        }
    }

    /// <summary>
    /// This class is used when the UNICODE_STRING is an output parameter.
    /// The allocatation of the buffer is handled elsewhere.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct UnicodeStringOut32 : IConvertToNative<UnicodeStringOut>
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr32 Buffer;

        public UnicodeStringOut Convert()
        {
            return new UnicodeStringOut
            {
                Length = Length,
                MaximumLength = MaximumLength,
                Buffer = Buffer.Convert()
            };
        }
    }

    /// <summary>
    /// Structure to use when passing in a unicode string as a sub-structure.
    /// </summary>
    public struct UnicodeStringIn
    {
        ushort Length;
        ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        string Buffer;

        public UnicodeStringIn(string str)
        {
            Length = 0;
            MaximumLength = 0;
            Buffer = null;
            SetString(str);
        }

        public void SetString(string str)
        {
            if (str.Length > ushort.MaxValue / 2)
            {
                throw new ArgumentException("String too long for UnicodeString");
            }
            Length = (ushort)(str.Length * 2);
            MaximumLength = (ushort)((str.Length * 2) + 1);
            Buffer = str;
        }
    }

    /// <summary>
    /// This class is used when the UNICODE_STRING needs to be preallocated
    /// and then returned back from a caller.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public sealed class UnicodeStringAllocated : IDisposable
    {
        public UnicodeStringOut String;

        public UnicodeStringAllocated(int max_size)
        {
            String.Length = 0;
            String.MaximumLength = (ushort)max_size;
            String.Buffer = Marshal.AllocHGlobal(String.MaximumLength);
        }

        public UnicodeStringAllocated() : this(MaxStringLength)
        {
        }

        public UnicodeStringAllocated(string str)
        {
            String.Length = (ushort)(str.Length * 2);
            String.MaximumLength = (ushort)(String.Length + 2);
            String.Buffer = Marshal.StringToHGlobalUni(str);
        }

        public const int MaxStringLength = ushort.MaxValue - 1;

        public override string ToString()
        {
            return String.ToString();
        }

        private void DisposeUnmanaged()
        {
            if (String.Buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(String.Buffer);
                String.Buffer = IntPtr.Zero;
            }
        }

        public void Dispose()
        {
            DisposeUnmanaged();
            GC.SuppressFinalize(this);
        }

        ~UnicodeStringAllocated()
        {
            DisposeUnmanaged();
        }
    }

    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern void RtlFreeUnicodeString([In, Out] ref UnicodeStringOut UnicodeString);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern char RtlUpcaseUnicodeChar(char SourceCharacter);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus RtlUpcaseUnicodeString(
            ref UnicodeStringOut DestinationString,
            UnicodeString SourceString,
            bool AllocateDestinationString
        );

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern char RtlDowncaseUnicodeChar(char SourceCharacter);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus RtlDowncaseUnicodeString(
            ref UnicodeStringOut DestinationString,
            UnicodeString SourceString,
            bool AllocateDestinationString
        );
    }
#pragma warning restore 1591
}
