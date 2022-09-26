//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Linq;
using System.Security.Cryptography;

namespace NtApiDotNet.Utilities.Security
{
    /// <summary>
    /// Basic implementation of ARC4.
    /// </summary>
    public sealed class ARC4 : ICryptoTransform
    {
        #region Private Members
        private readonly byte[] _key_schedule;
        private int _index;
        private int _swap_index;

        private static void Swap(byte[] s, int i, int j)
        {
            byte x = s[i];
            s[i] = s[j];
            s[j] = x;
        }

        private static byte[] CreateKeySchedule(byte[] key)
        {
            byte[] s = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
            int j = 0;
            for (int i = 0; i < 256; ++i)
            {
                j = (j + s[i] + key[i % key.Length]) & 0xFF;
                Swap(s, i, j);
            }
            return s;
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="key">The key for the encryption.</param>
        public ARC4(byte[] key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            _key_schedule = CreateKeySchedule(key);
        }
        #endregion

        #region Public Methods
        /// <summary>Transforms the specified region of the specified byte array.</summary>
        /// <param name="input_buffer">The input for which to compute the transform.</param>
        /// <param name="input_offset">The offset into the byte array from which to begin using data.</param>
        /// <param name="input_count">The number of bytes in the byte array to use as data.</param>
        /// <returns>The computed transform.</returns>
        public byte[] Transform(byte[] input_buffer, int input_offset, int input_count)
        {
            byte[] ret = new byte[input_count];
            Transform(input_buffer, input_offset, input_count, ret, 0);
            return ret;
        }

        /// <summary>Transforms the specified region of the input byte array and copies the resulting transform to the specified region of the output byte array.</summary>
        /// <param name="input_buffer">The input for which to compute the transform.</param>
        /// <param name="input_offset">The offset into the input byte array from which to begin using data.</param>
        /// <param name="input_count">The number of bytes in the input byte array to use as data.</param>
        /// <param name="output_buffer">The output to which to write the transform.</param>
        /// <param name="output_offset">The offset into the output byte array from which to begin writing data.</param>
        public void Transform(byte[] input_buffer, int input_offset, int input_count, byte[] output_buffer, int output_offset)
        {
            if (input_buffer is null)
            {
                throw new ArgumentNullException(nameof(input_buffer));
            }

            if (output_buffer is null)
            {
                throw new ArgumentNullException(nameof(output_buffer));
            }

            for (int p = 0; p < input_count; ++p)
            {
                _index = (_index + 1) & 0xFF;
                _swap_index = (_swap_index + _key_schedule[_index]) & 0xFF;
                Swap(_key_schedule, _index, _swap_index);
                byte k = _key_schedule[(_key_schedule[_index] + _key_schedule[_swap_index]) & 0xFF];
                output_buffer[p + output_offset] = (byte)(k ^ input_buffer[p + input_offset]);
            }
        }

        /// <summary>
        /// Encrypt, or decrypt an ARC4 stream.
        /// </summary>
        /// <param name="input_buffer">The data to encrypt/decrypt.</param>
        /// <returns>The resulting bytes.</returns>
        public byte[] Transform(byte[] input_buffer)
        {
            return Transform(input_buffer, 0, input_buffer.Length);
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Encrypt, or decrypt an ARC4 stream.
        /// </summary>
        /// <param name="data">The data to encrypt/decrypt.</param>
        /// <param name="offset">Offset into the data to decrypt.</param>
        /// <param name="length">Length of data to decrypt.</param>
        /// <param name="key">The key to decrypt.</param>
        /// <returns>The resulting bytes.</returns>
        public static byte[] Transform(byte[] data, int offset, int length, byte[] key)
        {
            return new ARC4(key).Transform(data, offset, length);
        }

        /// <summary>
        /// Encrypt, or decrypt an ARC4 stream.
        /// </summary>
        /// <param name="data">The data to encrypt/decrypt.</param>
        /// <param name="key">The key to decrypt.</param>
        /// <returns>The resulting bytes.</returns>
        public static byte[] Transform(byte[] data, byte[] key)
        {
            return Transform(data, 0, data.Length, key);
        }
        #endregion

        #region IDisposable Implementation
        void IDisposable.Dispose()
        {
        }
        #endregion

        #region ICryptoTransform Implementation
        int ICryptoTransform.InputBlockSize => 1;

        int ICryptoTransform.OutputBlockSize => 1;

        bool ICryptoTransform.CanTransformMultipleBlocks => true;

        bool ICryptoTransform.CanReuseTransform => true;

        int ICryptoTransform.TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            Transform(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            return inputCount;
        }

        byte[] ICryptoTransform.TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            return Transform(inputBuffer, inputOffset, inputCount);
        }
        #endregion
    }
}
