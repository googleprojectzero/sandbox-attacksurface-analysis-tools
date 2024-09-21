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

namespace NtApiDotNet.Utilities.IO
{
    /// <summary>
    /// Class to implement a scoped file lock.
    /// </summary>
    public sealed class NtFileScopedLock : IDisposable
    {
        private readonly NtFile _file;
        private readonly long _offset;
        private readonly long _size;

        private NtFileScopedLock(NtFile file, long offset, long size)
        {
            _file = file;
            _offset = offset;
            _size = size;
        }

        /// <summary>
        /// Lock part of a file.
        /// </summary>
        /// <param name="file">The file to lock.</param>
        /// <param name="offset">The offset into the file to lock</param>
        /// <param name="size">The number of bytes to lock</param>
        /// <param name="fail_immediately">True to fail immediately if the lock can't be taken</param>
        /// <param name="exclusive">True to do an exclusive lock</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtResult<NtFileScopedLock> Create(NtFile file, long offset, long size, bool fail_immediately, bool exclusive, bool throw_on_error)
        {
            return file.Lock(offset, size, fail_immediately, 
                exclusive, false).CreateResult(throw_on_error, () => new NtFileScopedLock(file, offset, size));
        }

        /// <summary>
        /// Lock part of a file.
        /// </summary>
        /// <param name="file">The file to lock.</param>
        /// <param name="offset">The offset into the file to lock</param>
        /// <param name="size">The number of bytes to lock</param>
        /// <param name="fail_immediately">True to fail immediately if the lock can't be taken</param>
        /// <param name="exclusive">True to do an exclusive lock</param>
        /// <returns>The NT status code.</returns>
        public static NtFileScopedLock Create(NtFile file, long offset, long size, bool fail_immediately, bool exclusive)
        {
            return Create(file, offset, size, fail_immediately, exclusive, true).Result;
        }

        /// <summary>
        /// Unlock the file.
        /// </summary>
        public void Dispose()
        {
            try
            {
                _file.Unlock(_offset, _size, false);
            }
            catch (ObjectDisposedException)
            {
            }
        }
    }
}
