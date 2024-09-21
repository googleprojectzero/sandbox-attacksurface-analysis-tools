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

using NtCoreLib.Image.Security;
using System;
using System.IO;

namespace NtCoreLib.Kernel.Process;

/// <summary>
/// Class which represents the configuration for a trustlet.
/// </summary>
public sealed class NtProcessTrustletConfig
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
        MemoryStream stm = new();
        BinaryWriter writer = new(stm);
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
