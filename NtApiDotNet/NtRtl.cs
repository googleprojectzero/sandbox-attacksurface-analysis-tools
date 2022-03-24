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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591

    /// <summary>
    /// Compression format for RtlDecompressBuffer.
    /// </summary>
    [Flags]
    public enum RtlCompressionFormat : short
    {
        None = 0,
        Default = 1,
        LZNT1 = 2,
        XPRESS = 3,
        XPRESS_HUFF = 4,
        Maximum = 0x100,
        Hiber = 0x200
    }

    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern int RtlNtStatusToDosError(NtStatus status);

        [DllImport("ntdll.dll")]
        public static extern int RtlNtStatusToDosErrorNoTeb(NtStatus status);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlGetLastNtStatus();

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlGetCompressionWorkSpaceSize(
          RtlCompressionFormat CompressionFormatAndEngine,
          out int CompressBufferWorkSpaceSize,
          out int CompressFragmentWorkSpaceSize
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlCompressBuffer(
          RtlCompressionFormat CompressionFormatAndEngine,
          [In] byte[] UncompressedBuffer,
          int UncompressedBufferSize,
          [Out] byte[] CompressedBuffer,
          int CompressedBufferSize,
          int UncompressedChunkSize,
          out int FinalCompressedSize,
          byte[] WorkSpace
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlDecompressBuffer(
          RtlCompressionFormat CompressionFormat,
          [In] byte[] UncompressedBuffer,
          int UncompressedBufferSize,
          [Out] byte[] CompressedBuffer,
          int CompressedBufferSize,
          out int FinalUncompressedSize
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlDecompressBufferEx(
          RtlCompressionFormat CompressionFormat,
          [In] byte[] UncompressedBuffer,
          int UncompressedBufferSize,
          [Out] byte[] CompressedBuffer,
          int CompressedBufferSize,
          out int FinalUncompressedSize,
          byte[] WorkSpace
        );
    }
#pragma warning restore 1591
}
