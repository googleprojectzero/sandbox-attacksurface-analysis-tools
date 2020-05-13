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

namespace NtApiDotNet.Utilities.Memory
{
    /// <summary>
    /// Class to compress and decompress buffers using RtlCompressionBuffer.
    /// </summary>
    public static class NtCompression
    {
        private static NtStatus Decompress(RtlCompressionFormat format, byte[] compressed_buffer, byte[] uncompressed_buffer, out int final_size)
        {
            if (format == RtlCompressionFormat.XPRESS_HUFF)
            {
                NtStatus status = NtRtl.RtlGetCompressionWorkSpaceSize(format, out int compress_size, out int fragment_size);
                if (!status.IsSuccess())
                {
                    final_size = 0;
                    return status;
                }
                byte[] workspace = new byte[compress_size];
                return NtRtl.RtlDecompressBufferEx(format, uncompressed_buffer, uncompressed_buffer.Length,
                        compressed_buffer, compressed_buffer.Length, out final_size, workspace);
            }
            return NtRtl.RtlDecompressBuffer(format, uncompressed_buffer, uncompressed_buffer.Length,
                compressed_buffer, compressed_buffer.Length, out final_size);
        }

        /// <summary>
        /// Decompress a buffer.
        /// </summary>
        /// <param name="format">The compression format used.</param>
        /// <param name="compressed_buffer">The compressed buffer.</param>
        /// <param name="uncompressed_length">The expected uncompressed length.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The uncompressed buffer.</returns>
        public static NtResult<byte[]> DecompressBuffer(RtlCompressionFormat format, byte[] compressed_buffer, int uncompressed_length, bool throw_on_error)
        {
            byte[] uncompressed_buffer = new byte[uncompressed_length];
            return Decompress(format, compressed_buffer, uncompressed_buffer, out int final_size).CreateResult(throw_on_error, () =>
            {
                if (uncompressed_buffer.Length != final_size)
                    Array.Resize(ref uncompressed_buffer, final_size);
                return uncompressed_buffer;
            }
            );
        }

        /// <summary>
        /// Decompress a buffer.
        /// </summary>
        /// <param name="format">The compression format used.</param>
        /// <param name="compressed_buffer">The compressed buffer.</param>
        /// <param name="uncompressed_length">The expected uncompressed length.</param>
        /// <returns>The uncompressed buffer.</returns>
        public static byte[] DecompressBuffer(RtlCompressionFormat format, byte[] compressed_buffer, int uncompressed_length)
        {
            return DecompressBuffer(format, compressed_buffer, uncompressed_length, true).Result;
        }
    }
}
