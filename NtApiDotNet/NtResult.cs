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

namespace NtApiDotNet
{
    /// <summary>
    /// A structure to return the result of an NT system call with status.
    /// This allows a function to return both a status code and a result
    /// without having to resort to out parameters.
    /// </summary>
    /// <typeparam name="T">The result type.</typeparam>
    public struct NtResult<T> : IDisposable
    {
        private readonly T _result;

        /// <summary>
        /// The NT status code.
        /// </summary>
        public NtStatus Status { get; }
        /// <summary>
        /// The result of the NT call.
        /// </summary>
        public T Result
        {
            get
            {
                System.Diagnostics.Debug.Assert(Status.IsSuccess());
                return _result;
            }
        }
        /// <summary>
        /// Get the result object or throw an exception if status code is an error.
        /// </summary>
        /// <returns>The result NT result.</returns>
        /// <exception cref="NtException">Thrown if status code is an error.</exception>
        public T GetResultOrThrow()
        {
            Status.ToNtException();
            return Result;
        }

        /// <summary>
        /// Get the result object or a default value if an error occurred.
        /// </summary>
        /// <param name="default_value">The default value to return.</param>
        /// <returns>The result or the default if an error occurred.</returns>
        public T GetResultOrDefault(T default_value)
        {
            if (IsSuccess)
                return _result;
            return default_value;
        }

        /// <summary>
        /// Get the result object or a default value if an error occurred.
        /// </summary>
        /// <returns>The result or the default if an error occurred.</returns>
        public T GetResultOrDefault()
        {
            return GetResultOrDefault(default);
        }

        /// <summary>
        /// Is the result successful.
        /// </summary>
        public bool IsSuccess => Status.IsSuccess();

        /// <summary>
        /// Map result to a different type.
        /// </summary>
        /// <typeparam name="S">The different type to map to.</typeparam>
        /// <param name="map_func">A function to map the result.</param>
        /// <returns>The mapped result.</returns>
        public NtResult<S> Map<S>(Func<T, S> map_func)
        {
            if (IsSuccess)
            {
                return new NtResult<S>(Status, map_func(Result));
            }
            return new NtResult<S>(Status, default);
        }

        /// <summary>
        /// Cast result to a different type.
        /// </summary>
        /// <typeparam name="S">The different type to cast to.</typeparam>
        /// <returns>The mapped result.</returns>
        public NtResult<S> Cast<S>()
        {
            return Map(d => (S)(object)d);
        }

        /// <summary>
        /// Dispose result.
        /// </summary>
        public void Dispose()
        {
            using (_result as IDisposable) { }
        }

        /// <summary>
        /// Create a result from an error.
        /// </summary>
        /// <param name="status">The error status code.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result.</returns>
        public static NtResult<T> CreateResultFromError(NtStatus status, bool throw_on_error)
        {
            return status.CreateResultFromError<T>(throw_on_error);
        }

        internal NtResult(NtStatus status, T result)
        {
            Status = status;
            _result = result;
        }
    }
}
