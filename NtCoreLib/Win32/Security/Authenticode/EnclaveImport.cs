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

using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authenticode
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_ENCLAVE_IMPORT
    {
        public ImageEnclaveImportMatchType MatchType;
        public int MinimumSecurityVersion;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] UniqueOrAuthorID;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] FamilyID;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ImageID;
        public int ImportName;
        public int Reserved;
    }

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public enum ImageEnclaveImportMatchType
    {
        None = 0,
        UniqueId = 1,
        AuthorId = 2,
        FamilyId = 3,
        ImageId = 4,
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member

    /// <summary>
    /// Class to represent an enclave import.
    /// </summary>
    public sealed class EnclaveImport
    {
        /// <summary>
        /// Match type for the import.
        /// </summary>
        public ImageEnclaveImportMatchType MatchType { get; }
        /// <summary>
        /// Minimum security version.
        /// </summary>
        public int MinimumSecurityVersion { get; }
        /// <summary>
        /// Unique or author ID.
        /// </summary>
        public byte[] UniqueOrAuthorID { get; }
        /// <summary>
        /// Family ID.
        /// </summary>
        public byte[] FamilyID { get; }
        /// <summary>
        /// Image ID.
        /// </summary>
        public byte[] ImageID { get; }
        /// <summary>
        /// Import name.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// ToString method.
        /// </summary>
        /// <returns>The name of the import.</returns>
        public override string ToString()
        {
            return Name;
        }

        internal EnclaveImport(IMAGE_ENCLAVE_IMPORT import, string name)
        {
            MatchType = import.MatchType;
            MinimumSecurityVersion = import.MinimumSecurityVersion;
            UniqueOrAuthorID = import.UniqueOrAuthorID;
            FamilyID = import.FamilyID;
            ImageID = import.ImageID;
            Name = name;
        }
    }
}
