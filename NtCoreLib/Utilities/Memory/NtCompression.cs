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
                NtStatus status = NtRtl.RtlGetCompressionWorkSpaceSize(format, out int compress_size, out int _);
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

        private static byte[] GetBuffer(byte[] buffer, int size)
        {
            if (buffer.Length != size)
                Array.Resize(ref buffer, size);
            return buffer;
        }

        /// <summary>
        /// Decompress a buffer.
        /// </summary>
        /// <param name="format">The compression format used.</param>
        /// <param name="buffer">The compressed buffer.</param>
        /// <param name="uncompressed_length">The expected uncompressed length.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The uncompressed buffer.</returns>
        public static NtResult<byte[]> DecompressBuffer(RtlCompressionFormat format, byte[] buffer, int uncompressed_length, bool throw_on_error)
        {
            byte[] uncompressed_buffer = new byte[uncompressed_length];
            return Decompress(format, buffer, uncompressed_buffer, out int final_size)
                .CreateResult(throw_on_error, () => GetBuffer(uncompressed_buffer, final_size));
        }

        /// <summary>
        /// Decompress a buffer.
        /// </summary>
        /// <param name="format">The compression format used.</param>
        /// <param name="buffer">The compressed buffer.</param>
        /// <param name="uncompressed_length">The expected uncompressed length.</param>
        /// <returns>The uncompressed buffer.</returns>
        public static byte[] DecompressBuffer(RtlCompressionFormat format, byte[] buffer, int uncompressed_length)
        {
            return DecompressBuffer(format, buffer, uncompressed_length, true).Result;
        }

        /// <summary>
        /// Decompress a buffer, where the uncompressed size isn't known.
        /// </summary>
        /// <param name="format">The compression format used.</param>
        /// <param name="buffer">The compressed buffer.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The uncompressed buffer.</returns>
        public static NtResult<byte[]> DecompressBuffer(RtlCompressionFormat format, byte[] buffer, bool throw_on_error)
        {
            int uncompressed_length = buffer.Length * 2;
            while(true)
            {
                byte[] uncompressed_buffer = new byte[uncompressed_length];
                NtStatus status = Decompress(format, buffer, uncompressed_buffer, out int final_size);
                if (status.IsSuccess())
                    return GetBuffer(uncompressed_buffer, final_size).CreateResult();
                if (status != NtStatus.STATUS_BAD_COMPRESSION_BUFFER)
                    return status.CreateResultFromError<byte[]>(throw_on_error);
                uncompressed_length *= 2;
            }
        }

        /// <summary>
        /// Decompress a buffer, where the uncompressed size isn't known.
        /// </summary>
        /// <param name="format">The compression format used.</param>
        /// <param name="buffer">The compressed buffer.</param>
        /// <returns>The uncompressed buffer.</returns>
        public static byte[] DecompressBuffer(RtlCompressionFormat format, byte[] buffer)
        {
            return DecompressBuffer(format, buffer, true).Result;
        }

        /// <summary>
        /// Compress a buffer.
        /// </summary>
        /// <param name="format">The compression format used.</param>
        /// <param name="buffer">The uncompressed buffer.</param>
        /// <param name="chunk_size">The chunk size for the compression. Typically should be 4096.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The compressed buffer.</returns>
        public static NtResult<byte[]> CompressBuffer(RtlCompressionFormat format, byte[] buffer, int chunk_size, bool throw_on_error)
        {
            NtStatus status = NtRtl.RtlGetCompressionWorkSpaceSize(format, out int compress_size, out int _);
            if (!status.IsSuccess())
                return status.CreateResultFromError<byte[]>(throw_on_error);
            byte[] workspace = new byte[compress_size];
            int compressed_size = buffer.Length;
            do
            {
                byte[] compressed_buffer = new byte[compressed_size];
                status = NtRtl.RtlCompressBuffer(format, buffer, buffer.Length, compressed_buffer, compressed_buffer.Length,
                    chunk_size, out int final_compressed_size, workspace);
                if (status.IsSuccess())
                {
                    Array.Resize(ref compressed_buffer, final_compressed_size);
                    return compressed_buffer.CreateResult();
                }
                compressed_size += 0x10000;
            }
            while (status == NtStatus.STATUS_BUFFER_TOO_SMALL);
            return status.CreateResultFromError<byte[]>(throw_on_error);
        }

        /// <summary>
        /// Compress a buffer.
        /// </summary>
        /// <param name="format">The compression format used.</param>
        /// <param name="buffer">The uncompressed buffer.</param>
        /// <param name="chunk_size">The chunk size for the compression. Typically should be 4096.</param>
        /// <returns>The compressed buffer.</returns>
        public static byte[] CompressBuffer(RtlCompressionFormat format, byte[] buffer, int chunk_size = 4096)
        {
            return CompressBuffer(format, buffer, chunk_size, true).Result;
        }
    }
}
