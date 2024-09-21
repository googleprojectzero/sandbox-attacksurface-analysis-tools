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
        #region Public Properties

        /// <summary>
        /// Handle to the port section.
        /// </summary>
        public SafeAlpcPortSectionHandle Handle { get; }

        /// <summary>
        /// Size of the port section.
        /// </summary>
        public long Size { get; }

        /// <summary>
        ///The actual section size.
        /// </summary>
        public long ActualSectionSize { get; }

        #endregion

        #region Constructors

        internal AlpcPortSection(AlpcHandle handle, IntPtr size, IntPtr actual_section_size, NtAlpc port)
        {
            Handle = new SafeAlpcPortSectionHandle(handle, true, port);
            Size = size.ToInt64();
            ActualSectionSize = actual_section_size.ToInt64();
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Create a new section view attribute.
        /// </summary>
        /// <param name="flags">Specify the flags for the data view attribute.</param>
        /// <param name="view_size">The section view size.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The section view attribute.</returns>
        public NtResult<SafeAlpcDataViewBuffer> CreateSectionView(AlpcDataViewAttrFlags flags, long view_size, bool throw_on_error)
        {
            AlpcDataViewAttr attr = new AlpcDataViewAttr()
            {
                SectionHandle = Handle.DangerousGetHandle().ToInt64(),
                ViewSize = new IntPtr(view_size)
            };
            return NtSystemCalls.NtAlpcCreateSectionView(Handle.Port.Handle, 0, ref attr).CreateResult(throw_on_error,
                () => new SafeAlpcDataViewBuffer(attr.ViewBase, view_size, Handle, flags, true));
        }

        /// <summary>
        /// Create a new section view attribute.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The section view attribute.</returns>
        public NtResult<SafeAlpcDataViewBuffer> CreateSectionView(bool throw_on_error)
        {
            return CreateSectionView(AlpcDataViewAttrFlags.None, Size, throw_on_error);
        }

        /// <summary>
        /// Create a new section view attribute.
        /// </summary>
        /// <param name="flags">Specify the flags for the data view attribute.</param>
        /// <param name="view_size">The section view size.</param>
        /// <returns>The section view attribute.</returns>
        public SafeAlpcDataViewBuffer CreateSectionView(AlpcDataViewAttrFlags flags, long view_size)
        {
            return CreateSectionView(flags, view_size, true).Result;
        }

        /// <summary>
        /// Create a new section view attribute.
        /// </summary>
        /// <returns>The section view attribute.</returns>
        public SafeAlpcDataViewBuffer CreateSectionView()
        {
            return CreateSectionView(AlpcDataViewAttrFlags.None, Size);
        }

        /// <summary>
        /// Dispose of the port section.
        /// </summary>
        public void Dispose()
        {
            Handle.Dispose();
        }

        #endregion
    }
}
