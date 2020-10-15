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

using NtApiDotNet.Win32.Security.Authenticode;
using System;

namespace NtApiDotNet
{
    /// <summary>
    /// Class which represents the configuration for a trustlet.
    /// </summary>
    public class NtProcessTrustletConfig
    {
        #region Public Properties
        /// <summary>
        /// The ID of the trustlet.
        /// </summary>
        public long Id { get; set; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The object as a string.</returns>
        public override string ToString()
        {
            return $"Trustlet Id: {Id}";
        }
        #endregion

        #region Static Methods

        /// <summary>
        /// Create a trustlet configuration from an image file.
        /// </summary>
        /// <param name="path">The path to the image file. Should be a native path.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The trustlet configuration.</returns>
        public static NtResult<NtProcessTrustletConfig> CreateFromFile(string path, bool throw_on_error)
        {
            return ImagePolicyMetadata.CreateFromFile($@"\\?\GLOBALROOT\{path}", 
                throw_on_error).Map(p => new NtProcessTrustletConfig(p.Id));
        }

        /// <summary>
        /// Create a trustlet configuration from an image file.
        /// </summary>
        /// <param name="path">The path to the image file. Should be a win32 path.</param>
        /// <returns>The trustlet configuration.</returns>
        public static NtProcessTrustletConfig CreateFromFile(string path)
        {
            return CreateFromFile(path, true).Result;
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor
        /// </summary>
        public NtProcessTrustletConfig()
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="id">The ID of the trustlet.</param>
        public NtProcessTrustletConfig(long id)
        {
            Id = id;
        }
        #endregion

        #region Internal Members
        internal byte[] ToArray()
        {
            return BitConverter.GetBytes(Id);
        }
        #endregion
    }
}
