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

using NtApiDotNet.Utilities.Memory;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authenticode
{
    /// <summary>
    /// Class to represnt image policy metadata.
    /// </summary>
    public sealed class ImagePolicyMetadata
    {
        #region Public Properties
        /// <summary>
        /// Version of the metadata.
        /// </summary>
        public int Version { get; }

        /// <summary>
        /// The ID of the trustlet.
        /// </summary>
        public long Id { get; }

        /// <summary>
        /// The optional policies for the trustlet.
        /// </summary>
        public IReadOnlyList<ImagePolicyEntry> Policies { get; }
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
        /// Extract image policy metadata from an image file.
        /// </summary>
        /// <param name="path">The path to the image file. Should be a win32 path.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The image policy metadata.</returns>
        public static NtResult<ImagePolicyMetadata> CreateFromFile(string path, bool throw_on_error)
        {
            using (var lib = SafeLoadLibraryHandle.LoadLibrary(path, LoadLibraryFlags.DontResolveDllReferences))
            {
                var policy = lib.GetProcAddress("__ImagePolicyMetadata");
                if (policy == IntPtr.Zero)
                    return NtStatus.STATUS_NOT_FOUND.CreateResultFromError<ImagePolicyMetadata>(throw_on_error);

                var meta_data = policy.ReadStruct<IMAGE_POLICY_METADATA>();

                if (meta_data.Version != 1)
                    return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<ImagePolicyMetadata>(throw_on_error);

                policy += Marshal.SizeOf(meta_data);
                int stride = Marshal.SizeOf(typeof(IMAGE_POLICY_ENTRY));

                List<ImagePolicyEntry> entries = new List<ImagePolicyEntry>();
                var entry = policy.ReadStruct<IMAGE_POLICY_ENTRY>();
                while (entry.Type != ImagePolicyEntryType.None)
                {
                    entries.Add(new ImagePolicyEntry(entry.Type, entry.PolicyId, entry.Value));
                    policy += stride;
                    entry = policy.ReadStruct<IMAGE_POLICY_ENTRY>();
                }

                return new ImagePolicyMetadata(1, meta_data.ApplicationId, entries).CreateResult();
            }
        }

        /// <summary>
        /// Extract image policy metadata from an image file.
        /// </summary>
        /// <param name="path">The path to the image file. Should be a win32 path.</param>
        /// <returns>The image policy metadata.</returns>
        public static ImagePolicyMetadata CreateFromFile(string path)
        {
            return CreateFromFile(path, true).Result;
        }

        #endregion

        #region Private Members
        private ImagePolicyMetadata(int version, long id, List<ImagePolicyEntry> policies)
        {
            Version = version;
            Id = id;
            Policies = policies;
        }
        #endregion
    }
}
