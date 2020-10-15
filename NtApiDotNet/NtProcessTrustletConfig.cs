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

using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public enum ImagePolicyEntryType
    {
        None = 0,
        Bool,
        Int8,
        UInt8,
        Int16,
        UInt16,
        Int32,
        UInt32,
        Int64,
        UInt64,
        AnsiString,
        UnicodeString
    }

    /// <summary>
    /// Image policy ID.
    /// </summary>
    public enum ImagePolicyId
    {
        None = 0,
        Etw,
        Debug,
        CrashDump,
        CrashDumpKey,
        CrashDumpKeyGuid,
        ParentSd,
        ParentSdRev,
        Svn,
        DeviceId,
        Capability,
        ScenarioId
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct IMAGE_POLICY_ENTRY_UNION
    {
        [FieldOffset(0)]
        public IntPtr None;
        [MarshalAs(UnmanagedType.U1), FieldOffset(0)]
        public bool BoolValue;
        [FieldOffset(0)]
        public sbyte Int8Value;
        [FieldOffset(0)]
        public byte UInt8Value;
        [FieldOffset(0)]
        public short Int16Value;
        [FieldOffset(0)]
        public ushort UInt16Value;
        [FieldOffset(0)]
        public int Int32Value;
        [FieldOffset(0)]
        public uint UInt32Value;
        [FieldOffset(0)]
        public long Int64Value;
        [FieldOffset(0)]
        public ulong UInt64Value;
        [FieldOffset(0)]
        public IntPtr AnsiStringValue;
        [FieldOffset(0)]
        public IntPtr UnicodeStringValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_POLICY_ENTRY
    {
        public ImagePolicyEntryType Type;
        public ImagePolicyId PolicyId;
        public IMAGE_POLICY_ENTRY_UNION Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_POLICY_METADATA
    {
        public byte Version;
        public long ApplicationId;
    }


#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member

    /// <summary>
    /// Image policy entry.
    /// </summary>
    public sealed class ImagePolicyEntry
    {
        /// <summary>
        /// Type of entry.
        /// </summary>
        public ImagePolicyEntryType Type { get; }
        /// <summary>
        /// Policy ID.
        /// </summary>
        public ImagePolicyId PolicyId { get; }
        /// <summary>
        /// Value of entry.
        /// </summary>
        public object Value { get; }

        private static object GetValue(ImagePolicyEntryType type, IMAGE_POLICY_ENTRY_UNION union)
        {
            switch (type)
            {
                case ImagePolicyEntryType.Bool:
                    return union.BoolValue;
                case ImagePolicyEntryType.Int16:
                    return union.Int16Value;
                case ImagePolicyEntryType.Int32:
                    return union.Int32Value;
                case ImagePolicyEntryType.Int64:
                    return union.Int64Value;
                case ImagePolicyEntryType.Int8:
                    return union.Int8Value;
                case ImagePolicyEntryType.UInt16:
                    return union.UInt16Value;
                case ImagePolicyEntryType.UInt32:
                    return union.UInt32Value;
                case ImagePolicyEntryType.UInt64:
                    return union.UInt64Value;
                case ImagePolicyEntryType.UInt8:
                    return union.UInt8Value;
                case ImagePolicyEntryType.UnicodeString:
                    return Marshal.PtrToStringUni(union.UnicodeStringValue);
                case ImagePolicyEntryType.AnsiString:
                    return Marshal.PtrToStringAnsi(union.AnsiStringValue);
                default:
                    return null;
            }
        }

        internal ImagePolicyEntry(ImagePolicyEntryType type, ImagePolicyId policy_id, IMAGE_POLICY_ENTRY_UNION union)
        {
            Type = type;
            PolicyId = policy_id;
            Value = GetValue(type, union);
        }
    }

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
        /// Create a trustlet configuration from an image file.
        /// </summary>
        /// <param name="path">The path to the image file. Should be a win32 path.</param>
        /// <returns>The trustlet configuration.</returns>
        public static NtProcessTrustletConfig CreateFromFile(string path)
        {
            using (var lib = SafeLoadLibraryHandle.LoadLibrary(path, LoadLibraryFlags.DontResolveDllReferences))
            {
                var policy = lib.GetProcAddress("__ImagePolicyMetadata");
                if (policy == IntPtr.Zero)
                    throw new ArgumentException("Couldn't find policy export.");

                IMAGE_POLICY_METADATA meta_data = (IMAGE_POLICY_METADATA)Marshal.PtrToStructure(policy, typeof(IMAGE_POLICY_METADATA));

                if (meta_data.Version != 1)
                    throw new ArgumentException("Invalid policy version.");

                policy += Marshal.SizeOf(meta_data);
                int stride = Marshal.SizeOf(typeof(IMAGE_POLICY_ENTRY));

                List<ImagePolicyEntry> entries = new List<ImagePolicyEntry>();
                IMAGE_POLICY_ENTRY entry = (IMAGE_POLICY_ENTRY)Marshal.PtrToStructure(policy, typeof(IMAGE_POLICY_ENTRY));
                while (entry.Type != ImagePolicyEntryType.None)
                {
                    entries.Add(new ImagePolicyEntry(entry.Type, entry.PolicyId, entry.Value));
                    policy += stride;
                    entry = (IMAGE_POLICY_ENTRY)Marshal.PtrToStructure(policy, typeof(IMAGE_POLICY_ENTRY));
                }

                return new NtProcessTrustletConfig(meta_data.ApplicationId, entries);
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor
        /// </summary>
        public NtProcessTrustletConfig() : this(0, null)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="id">The ID of the trustlet.</param>
        public NtProcessTrustletConfig(long id) : this(id, null)
        {
        }
        #endregion

        #region Internal Members

        internal NtProcessTrustletConfig(long id, List<ImagePolicyEntry> entries)
        {
            Id = id;
            Policies = (entries ?? new List<ImagePolicyEntry>()).AsReadOnly();
        }

        internal byte[] ToArray()
        {
            return BitConverter.GetBytes(Id);
        }
        #endregion
    }
}
