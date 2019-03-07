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
    /// Class to represent an ALPC port section.
    /// </summary>
    public sealed class AlpcPortSection : IDisposable
    {
        #region Private Members
        private readonly NtAlpc _port;
        #endregion

        #region Public Properties

        /// <summary>
        /// Handle to the port section.
        /// </summary>
        public long Handle { get; private set; }

        /// <summary>
        /// Size of the port section.
        /// </summary>
        public long Size { get; }

        #endregion

        #region Constructors

        internal AlpcPortSection(AlpcHandle handle, IntPtr size, NtAlpc port)
        {
            Handle = handle.Value;
            Size = size.ToInt64();
            _port = port;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Create a new section view attribute.
        /// </summary>
        /// <param name="view_size">The section view size.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The section view attribute.</returns>
        public NtResult<AlpcDataViewMessageAttribute> CreateSectionView(long view_size, bool throw_on_error)
        {
            AlpcDataViewAttr attr = new AlpcDataViewAttr()
            {
                SectionHandle = Handle,
                ViewSize = new IntPtr(view_size)
            };
            return NtSystemCalls.NtAlpcCreateSectionView(_port.Handle, 0, ref attr).CreateResult(throw_on_error, 
                () => new AlpcDataViewMessageAttribute(attr, _port));
        }

        /// <summary>
        /// Create a new section view attribute.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The section view attribute.</returns>
        public NtResult<AlpcDataViewMessageAttribute> CreateSectionView(bool throw_on_error)
        {
            return CreateSectionView(Size, throw_on_error);
        }

        /// <summary>
        /// Create a new section view attribute.
        /// </summary>
        /// <param name="view_size">The section view size.</param>
        /// <returns>The section view attribute.</returns>
        public AlpcDataViewMessageAttribute CreateSectionView(long view_size)
        {
            return CreateSectionView(view_size, true).Result;
        }

        /// <summary>
        /// Create a new section view attribute.
        /// </summary>
        /// <returns>The section view attribute.</returns>
        public AlpcDataViewMessageAttribute CreateSectionView()
        {
            return CreateSectionView(Size);
        }

        /// <summary>
        /// Dispose of the port section.
        /// </summary>
        public void Dispose()
        {
            if (!_port.Handle.IsClosed)
            {
                NtSystemCalls.NtAlpcDeletePortSection(_port.Handle, AlpcDeletePortSectionFlags.None, Handle);
                Handle = 0;
            }
        }

        #endregion
    }
}
