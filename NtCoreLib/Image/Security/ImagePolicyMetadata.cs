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

using NtCoreLib.Image.Interop;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtCoreLib.Image.Security;

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
    internal static NtResult<ImagePolicyMetadata> CreateFromImageFile(ImageFile image, bool throw_on_error)
    {
        var policy_exp = image.GetProcAddress("__ImagePolicyMetadata", false);
        if (!policy_exp.IsSuccess)
            return policy_exp.Cast<ImagePolicyMetadata>();

        IntPtr policy = policy_exp.Result;
        var reader = image.ToMemoryReader();
        var meta_data = reader.ReadStruct<IMAGE_POLICY_METADATA>(policy);

        if (meta_data.Version != 1)
            return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<ImagePolicyMetadata>(throw_on_error);

        policy += Marshal.SizeOf(meta_data);
        int stride = Marshal.SizeOf(typeof(IMAGE_POLICY_ENTRY));

        List<ImagePolicyEntry> entries = new();
        var entry = reader.ReadStruct<IMAGE_POLICY_ENTRY>(policy);
        while (entry.Type != ImagePolicyEntryType.None)
        {
            entries.Add(new ImagePolicyEntry(entry.Type, entry.PolicyId, entry.Value, reader));
            policy += stride;
            entry = reader.ReadStruct<IMAGE_POLICY_ENTRY>(policy);
        }

        return new ImagePolicyMetadata(1, meta_data.ApplicationId, entries).CreateResult();
    }

    internal static NtResult<ImagePolicyMetadata> CreateFromFile(string path, bool throw_on_error)
    {
        try
        {
            using var lib = ImageFile.Parse(path, default, throw_on_error);
            if (!lib.IsSuccess)
                return lib.Cast<ImagePolicyMetadata>();
            return CreateFromImageFile(lib.Result, throw_on_error);
        }
        catch
        {
            return NtStatus.STATUS_IMAGE_MACHINE_TYPE_MISMATCH.CreateResultFromError<ImagePolicyMetadata>(throw_on_error);
        }
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
