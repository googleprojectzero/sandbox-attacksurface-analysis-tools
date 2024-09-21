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
using System.IO;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    internal enum PsTrustletAccessRights : byte
    {
        None = 0,
        Trustlet = 1,
        Ntos = 2,
        WriteHandle = 4,
        ReadHandle = 8,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_TRUSTLET_ATTRIBUTE_TYPE 
    {
        public int AttributeType;

        public byte Version => (byte)(AttributeType & 0xFF);
        public byte DataCount => (byte)((AttributeType >> 8) & 0xFF);
        public byte SemanticType => (byte)((AttributeType >> 16) & 0xFF);
        public PsTrustletAccessRights AccessRights =>  (PsTrustletAccessRights)((AttributeType >> 24) & 0xFF);

        public static PS_TRUSTLET_ATTRIBUTE_TYPE TrustletType_MailboxKey = new PS_TRUSTLET_ATTRIBUTE_TYPE() { AttributeType = 0x100200 };
        public static PS_TRUSTLET_ATTRIBUTE_TYPE TrustletType_CollaborationId = new PS_TRUSTLET_ATTRIBUTE_TYPE() { AttributeType = 0x110200 };
        public static PS_TRUSTLET_ATTRIBUTE_TYPE TrustletType_VmId = new PS_TRUSTLET_ATTRIBUTE_TYPE() { AttributeType = 0x3130200 };
        public static PS_TRUSTLET_ATTRIBUTE_TYPE TrustletType_TkSessionId = new PS_TRUSTLET_ATTRIBUTE_TYPE() { AttributeType = 0x120400 };
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_TRUSTLET_ATTRIBUTE_HEADER
    {
        public PS_TRUSTLET_ATTRIBUTE_TYPE AttributeType;
        public int InstanceNumber;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Data")]
    internal struct PS_TRUSTLET_ATTRIBUTE_DATA
    {
        public PS_TRUSTLET_ATTRIBUTE_HEADER Header;
        public long Data;
    }

    [StructLayout(LayoutKind.Sequential), DataStart("Attributes")]
    internal struct PS_TRUSTLET_CREATE_ATTRIBUTES
    {
        public long TrustletIdentity;
        public PS_TRUSTLET_ATTRIBUTE_DATA Attributes;
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
        /// The mailbox key. Must be 2 longs.
        /// </summary>
        public long[] MailboxKey { get; set; }

        /// <summary>
        /// The collaboration ID. Must be 2 longs.
        /// </summary>
        public long[] CollaborationId { get; set; }

        /// <summary>
        /// The VM ID. Must be 2 longs.
        /// </summary>
        public long[] VmId { get; set; }

        /// <summary>
        /// The TK sessio ID. Must be 4 longs.
        /// </summary>
        public long[] TkSessionId { get; set; }

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
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write(Id);
            WriteAttribute(writer, PS_TRUSTLET_ATTRIBUTE_TYPE.TrustletType_CollaborationId, CollaborationId);
            WriteAttribute(writer, PS_TRUSTLET_ATTRIBUTE_TYPE.TrustletType_VmId, VmId);
            WriteAttribute(writer, PS_TRUSTLET_ATTRIBUTE_TYPE.TrustletType_MailboxKey, MailboxKey);
            WriteAttribute(writer, PS_TRUSTLET_ATTRIBUTE_TYPE.TrustletType_TkSessionId, TkSessionId);
            return stm.ToArray();
        }
        #endregion

        #region Private Members
        private void WriteAttribute(BinaryWriter writer, PS_TRUSTLET_ATTRIBUTE_TYPE type, long[] data)
        {
            if (data == null)
                return;
            if (data.Length != type.DataCount)
                throw new ArgumentException("Data length does not match type");
            writer.Write(type.AttributeType);
            writer.Write(0);
            foreach (var l in data)
            {
                writer.Write(l);
            }
        }
        #endregion
    }
}
