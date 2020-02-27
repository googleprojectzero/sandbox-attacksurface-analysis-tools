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
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    /// <summary>
    /// Interface to generically query an object.
    /// </summary>
    public interface INtObjectQueryInformation
    {
        NtResult<SafeHGlobalBuffer> QueryBuffer(int info_class, byte[] init_buffer, bool throw_on_error);
    }

    /// <summary>
    /// Interface to generically set an object.
    /// </summary>
    public interface INtObjectSetInformation
    {
        NtStatus SetBuffer(int info_class, SafeBuffer buffer, bool throw_on_error);
    }
#pragma warning restore 1591

    /// <summary>
    /// A derived class to add some useful functions such as Duplicate as well as generic Query and Set information methods.
    /// </summary>
    /// <typeparam name="O">The derived type to use as return values</typeparam>
    /// <typeparam name="A">An enum which represents the access mask values for the type</typeparam>
    /// <typeparam name="Q">An enum which represents the information class for query.</typeparam>
    /// <typeparam name="S">An enum which represents the information class for set.</typeparam>
    public abstract class NtObjectWithDuplicateAndInfo<O, A, Q, S> : NtObjectWithDuplicate<O, A>, INtObjectQueryInformation, INtObjectSetInformation where O : NtObject where A : Enum where Q : Enum where S : Enum
    {
        #region Constructors
        internal NtObjectWithDuplicateAndInfo(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        new internal class NtTypeFactoryImplBase : NtObjectWithDuplicate<O, A>.NtTypeFactoryImplBase
        {
            protected NtTypeFactoryImplBase(Type container_access_rights_type, bool can_open, MandatoryLabelPolicy default_policy)
                : base(container_access_rights_type, can_open, default_policy)
            {
            }

            protected NtTypeFactoryImplBase(Type container_access_rights_type, bool can_open)
                : base(container_access_rights_type, can_open)
            {
            }

            protected NtTypeFactoryImplBase(bool can_open, MandatoryLabelPolicy default_policy)
                : base(can_open, default_policy)
            {
            }

            protected NtTypeFactoryImplBase(bool can_open)
                : base(can_open)
            {
            }

            protected NtTypeFactoryImplBase()
                : base(false)
            {
            }

            public override IEnumerable<Enum> GetQueryInfoClass()
            {
                return Enum.GetValues(typeof(Q)).Cast<Enum>();
            }

            public override IEnumerable<Enum> GetSetInfoClass()
            {
                return Enum.GetValues(typeof(S)).Cast<Enum>();
            }
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Query a fixed structure from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual NtResult<T> Query<T>(Q info_class, T default_value, bool throw_on_error) where T : new()
        {
            using (var buffer = new SafeStructureInOutBuffer<T>(default_value))
            {
                return QueryInformation(info_class, buffer, out int return_length).CreateResult(throw_on_error, () => buffer.Result);
            }
        }

        /// <summary>
        /// Query a fixed structure from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public T Query<T>(Q info_class, T default_value) where T : new()
        {
            return Query(info_class, default_value, true).Result;
        }

        /// <summary>
        /// Query a fixed structure from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public T Query<T>(Q info_class) where T : new()
        {
            return Query(info_class, new T());
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual NtResult<SafeStructureInOutBuffer<T>> QueryBuffer<T>(Q info_class, T default_value, bool throw_on_error) where T : new()
        {
            NtStatus status;
            int return_length;
            // First try base size before trying to reallocate.
            using (var buffer = default_value.ToBuffer())
            {
                status = QueryInformation(info_class, buffer, out return_length);
                if (status.IsSuccess())
                {
                    return status.CreateResult(false, () => buffer.Detach());
                }
            }

            if (!IsInvalidBufferStatus(status))
            {
                return status.CreateResultFromError<SafeStructureInOutBuffer<T>>(throw_on_error);
            }

            // If the function returned a length then trust it.
            if (return_length > 0 && GetTrustReturnLength(info_class))
            {
                using (var buffer = new SafeStructureInOutBuffer<T>(default_value, return_length, false))
                {
                    return QueryInformation(info_class, buffer, out return_length).CreateResult(throw_on_error, () => buffer.Detach());
                }
            }

            // Function length can't be trusted, we'll need to brute force it.
            return_length = GetSmallestPower2(Marshal.SizeOf(typeof(T)));
            int max_length = GetMaximumBruteForceLength(info_class);
            while (return_length < max_length)
            {
                using (var buffer = new SafeStructureInOutBuffer<T>(default_value, return_length, false))
                {
                    status = QueryInformation(info_class, buffer, out int dummy_length);
                    if (status.IsSuccess())
                    {
                        return status.CreateResult(throw_on_error, () => buffer.Detach());
                    }
                    else if (!IsInvalidBufferStatus(status))
                    {
                        return status.CreateResultFromError<SafeStructureInOutBuffer<T>>(throw_on_error);
                    }
                    return_length *= 2;
                }
            }

            return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<SafeStructureInOutBuffer<T>>(throw_on_error);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="init_buffer">A buffer to initialize the initial query. Can be null.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual NtResult<SafeHGlobalBuffer> QueryRawBuffer(Q info_class, byte[] init_buffer, bool throw_on_error)
        {
            NtStatus status;
            int return_length;
            // First try base size before trying to reallocate.
            using (var buffer = init_buffer.ToBuffer())
            {
                status = QueryInformation(info_class, buffer, out return_length);
                if (status.IsSuccess())
                {
                    return status.CreateResult(false, () => buffer.Detach(return_length));
                }
            }

            if (!IsInvalidBufferStatus(status))
            {
                return status.CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
            }

            // If the function returned a length then trust it.
            if (return_length > 0 && GetTrustReturnLength(info_class))
            {
                using (var buffer = new SafeHGlobalBuffer(return_length))
                {
                    return QueryInformation(info_class, buffer, out return_length).CreateResult(throw_on_error, () => buffer.Detach(return_length));
                }
            }

            // Function length can't be trusted, we'll need to brute force it.
            return_length = 256;
            int max_length = GetMaximumBruteForceLength(info_class);
            while (return_length <= max_length)
            {
                using (var buffer = new SafeHGlobalBuffer(return_length))
                {
                    status = QueryInformation(info_class, buffer, out int dummy_length);
                    if (status.IsSuccess())
                    {
                        if (dummy_length > 0 && dummy_length < return_length)
                        {
                            return_length = dummy_length;
                        }
                        return status.CreateResult(throw_on_error, () => buffer.Detach(return_length));
                    }
                    else if (!IsInvalidBufferStatus(status))
                    {
                        return status.CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
                    }

                    return_length *= 2;
                }
            }

            return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<SafeHGlobalBuffer>(throw_on_error);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="init_buffer">A buffer to initialize the initial query. Can be null.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual SafeHGlobalBuffer QueryRawBuffer(Q info_class, byte[] init_buffer)
        {
            return QueryRawBuffer(info_class, init_buffer, true).Result;
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual SafeHGlobalBuffer QueryRawBuffer(Q info_class)
        {
            return QueryRawBuffer(info_class, null);
        }

        /// <summary>
        /// Query a variable buffer from the object and return as bytes.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="init_buffer">A buffer to initialize the initial query. Can be null.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual NtResult<byte[]> QueryRawBytes(Q info_class, byte[] init_buffer, bool throw_on_error)
        {
            using (var buffer = QueryRawBuffer(info_class, init_buffer, throw_on_error))
            {
                return buffer.Map(b => b.ToArray());
            }
        }

        /// <summary>
        /// Query a variable buffer from the object and return as bytes.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="init_buffer">A buffer to initialize the initial query. Can be null.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual byte[] QueryRawBytes(Q info_class, byte[] init_buffer)
        {
            return QueryRawBytes(info_class, init_buffer, true).Result;
        }

        /// <summary>
        /// Query a variable buffer from the object and return as bytes.
        /// </summary>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual byte[] QueryRawBytes(Q info_class)
        {
            return QueryRawBytes(info_class, null);
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <param name="default_value">A default value for the query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual SafeStructureInOutBuffer<T> QueryBuffer<T>(Q info_class, T default_value) where T : new()
        {
            return QueryBuffer(info_class, default_value, true).Result;
        }

        /// <summary>
        /// Query a variable buffer from the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to return.</typeparam>
        /// <param name="info_class">The information class to query.</param>
        /// <returns>The result of the query.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public SafeStructureInOutBuffer<T> QueryBuffer<T>(Q info_class) where T : new()
        {
            return QueryBuffer(info_class, new T(), true).Result;
        }

        /// <summary>
        /// Set a value to the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to set.</typeparam>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="value">The value to set. If you specify a SafeBuffer then it'll be passed directly.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual NtStatus Set<T>(S info_class, T value, bool throw_on_error) where T : struct
        {
            using (var buffer = value.ToBuffer())
            {
                return SetInformation(info_class, buffer).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Set a value to the object.
        /// </summary>
        /// <typeparam name="T">The type of structure to set.</typeparam>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="value">The value to set.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void Set<T>(S info_class, T value) where T : struct
        {
            Set(info_class, value, true);
        }

        /// <summary>
        /// Set a value to the object from a buffer.
        /// </summary>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="buffer">The value to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual NtStatus SetBuffer(S info_class, SafeBuffer buffer, bool throw_on_error)
        {
            return SetInformation(info_class, buffer).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Set a value to the object from a buffer..
        /// </summary>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="buffer">The value to set.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetBuffer(S info_class, SafeBuffer buffer)
        {
            SetBuffer(info_class, buffer, true);
        }

        /// <summary>
        /// Set a raw value to the object.
        /// </summary>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="value">The raw value to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual NtStatus SetBytes(S info_class, byte[] value, bool throw_on_error)
        {
            using (var buffer = value.ToBuffer())
            {
                return SetInformation(info_class, buffer).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Set a raw value to the object.
        /// </summary>
        /// <param name="info_class">The information class to set.</param>
        /// <param name="value">The raw value to set.</param>
        /// <returns>The NT status code of the set.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public virtual void SetBytes(S info_class, byte[] value)
        {
            SetBytes(info_class, value, true);
        }

        /// <summary>
        /// Method to query information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to return data in.</param>
        /// <param name="return_length">Return length from the query.</param>
        /// <returns>The NT status code for the query.</returns>
        public virtual NtStatus QueryInformation(Q info_class, SafeBuffer buffer, out int return_length)
        {
            return_length = 0;
            return NtStatus.STATUS_NOT_SUPPORTED;
        }

        /// <summary>
        /// Method to set information for this object type.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        /// <returns>The NT status code for the set.</returns>
        public virtual NtStatus SetInformation(S info_class, SafeBuffer buffer)
        {
            return NtStatus.STATUS_NOT_SUPPORTED;
        }

        #endregion

        #region Protected Methods
        /// <summary>
        /// Overriddable method to determine the maximum brute force length for query.
        /// </summary>
        /// <param name="info_class">Information class to key on if needs to return different sizes.</param>
        /// <returns>The maximum bytes to brute force. Returning 0 will disable brute force.</returns>
        protected virtual int GetMaximumBruteForceLength(Q info_class)
        {
            return 16 * 1024;
        }

        /// <summary>
        /// Overridable method to determine if the return length shouldn't be trusted for this info class when querying a variable buffer.
        /// </summary>
        /// <param name="info_class">Information class to key on.</param>
        /// <returns>True to trust the return length when querying a variable buffer.</returns>
        protected virtual bool GetTrustReturnLength(Q info_class)
        {
            return true;
        }

        #endregion

        #region Private Members
        private static bool IsInvalidBufferStatus(NtStatus status)
        {
            return status == NtStatus.STATUS_INFO_LENGTH_MISMATCH || status == NtStatus.STATUS_BUFFER_TOO_SMALL || status == NtStatus.STATUS_BUFFER_OVERFLOW;
        }

        private static int GetSmallestPower2(int size)
        {
            if (size <= 0)
            {
                throw new ArgumentException("Size must be greater than 0");
            }

            // Already a power of 2.
            if ((size & (size - 1)) == 0)
            {
                return size;
            }

            int bits = 0;
            int curr_size = size;
            while (curr_size != 0)
            {
                bits++;
                curr_size >>= 1;
            }

            curr_size = 1 << bits;
            return Math.Max(curr_size, size);
        }

        #endregion

        #region INtObjectQueryInformation Implementation
        NtResult<SafeHGlobalBuffer> INtObjectQueryInformation.QueryBuffer(int info_class, byte[] init_buffer, bool throw_on_error)
        {
            return QueryRawBuffer((Q)Enum.ToObject(typeof(Q), info_class), init_buffer, throw_on_error);
        }
        #endregion

        #region INtObjectSetInformation Implementation
        NtStatus INtObjectSetInformation.SetBuffer(int info_class, SafeBuffer buffer, bool throw_on_error)
        {
            return SetBuffer((S)Enum.ToObject(typeof(S), info_class), buffer, throw_on_error);
        }

        #endregion
    }
}
