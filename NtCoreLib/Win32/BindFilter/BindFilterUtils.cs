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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.BindFilter.Interop;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Win32.BindFilter;

/// <summary>
/// Utilities for interacting with the bind filter.
/// </summary>
public static class BindFilterUtils
{
    #region Public Static Members
    /// <summary>
    /// Create a bind link.
    /// </summary>
    /// <param name="virtual_path">The virtual path for the bind link.</param>
    /// <param name="backing_path">The backing path for the bind link.</param>
    /// <param name="flags">Optional flags.</param>
    /// <param name="exception_paths">Exception paths under the bind link.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    /// <exception cref="ArgumentNullException">Throw if a parameter is null.</exception>
    /// <remarks>This uses the Win32 bind link APIs which only exist from Windows 11 24H2.</remarks>
    public static NtStatus CreateBindLink(
        string virtual_path,
        string backing_path,
        CreateBindLinkFlags flags,
        IEnumerable<string> exception_paths, 
        bool throw_on_error)
    {
        if (virtual_path is null)
        {
            throw new ArgumentNullException(nameof(virtual_path));
        }

        if (backing_path is null)
        {
            throw new ArgumentNullException(nameof(backing_path));
        }

        string[] paths = exception_paths?.ToArray();
        int count = paths?.Length ?? 0;

        return NativeMethods.CreateBindLink(virtual_path, backing_path, 
            flags, count, paths).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Create a bind link.
    /// </summary>
    /// <param name="virtual_path">The virtual path for the bind link.</param>
    /// <param name="backing_path">The backing path for the bind link.</param>
    /// <param name="flags">Optional flags.</param>
    /// <param name="exception_paths">Exception paths under the bind link.</param>
    /// <exception cref="ArgumentNullException">Throw if a parameter is null.</exception>
    /// <remarks>This uses the Win32 bind link APIs which only exist from Windows 11 24H2.</remarks>
    public static void CreateBindLink(
        string virtual_path,
        string backing_path,
        CreateBindLinkFlags flags = 0,
        IEnumerable<string> exception_paths = null)
    {
        CreateBindLink(virtual_path, backing_path, flags, exception_paths, true);
    }

    /// <summary>
    /// Remove a bind link.
    /// </summary>
    /// <param name="virtual_path">The virtual path for the bind link.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    /// <exception cref="ArgumentNullException">Throw if a parameter is null.</exception>
    /// <remarks>This uses the Win32 bind link APIs which only exist from Windows 11 24H2.</remarks>
    public static NtStatus RemoveBindLink(
        string virtual_path, 
        bool throw_on_error)
    {
        if (virtual_path is null)
        {
            throw new ArgumentNullException(nameof(virtual_path));
        }

        return NativeMethods.RemoveBindLink(virtual_path).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Remove a bind link.
    /// </summary>
    /// <param name="virtual_path">The virtual path for the bind link.</param>
    /// <exception cref="ArgumentNullException">Throw if a parameter is null.</exception>
    /// <remarks>This uses the Win32 bind link APIs which only exist from Windows 11 24H2.</remarks>
    public static void RemoveBindLink(
        string virtual_path)
    {
        RemoveBindLink(virtual_path, true);
    }

    /// <summary>
    /// Setup a bind filter mapping.
    /// </summary>
    /// <param name="job">The job object associated with the mappings.</param>
    /// <param name="virtual_path">The root virtual path for the mappings.</param>
    /// <param name="exception_paths">List of exception paths.</param>
    /// <param name="flags">Flags for the mapping.</param>
    /// <param name="target_path">The target path for the mapping.</param>
    /// <param name="sid">The user SID associated with the mappings.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus SetupFilter(
        NtJob job,
        Sid sid,
        BfSetupFilterFlags flags,
        string virtual_path,
        string target_path,
        IEnumerable<string> exception_paths,
        bool throw_on_error)
    {
        using var sid_buffer = sid?.ToSafeBuffer() ?? SafeSidBufferHandle.Null;
        string[] paths = exception_paths?.ToArray();
        int count = paths?.Length ?? 0;

        return NativeMethods.BfSetupFilterEx(job.GetHandle(), sid_buffer, flags, virtual_path, 
            target_path, count == 0 ? null : paths, count).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Setup a bind filter mapping.
    /// </summary>
    /// <param name="job">The job object associated with the mappings.</param>
    /// <param name="virtual_path">The root virtual path for the mappings.</param>
    /// <param name="exception_paths">List of exception paths.</param>
    /// <param name="flags">Flags for the mapping.</param>
    /// <param name="target_path">The target path for the mapping.</param>
    /// <param name="sid">The user SID associated with the mappings.</param>
    public static void SetupFilter(
        NtJob job,
        Sid sid,
        BfSetupFilterFlags flags,
        string virtual_path,
        string target_path,
        IEnumerable<string> exception_paths)
    {
        SetupFilter(job, sid, flags, virtual_path, target_path, exception_paths, true);
    }

    /// <summary>
    /// Create a global bind filter mapping.
    /// </summary>
    /// <param name="virtual_path">The root virtual path for the mappings.</param>
    /// <param name="exception_paths">List of exception paths.</param>
    /// <param name="flags">Flags for the mapping.</param>
    /// <param name="target_path">The target path for the mapping.</param>
    public static void CreateGlobalMapping(
        BfSetupFilterFlags flags,
        string virtual_path,
        string target_path,
        params string[] exception_paths)
    {
        SetupFilter(null, null, flags, virtual_path, target_path, exception_paths);
    }

    /// <summary>
    /// Remove a mapping.
    /// </summary>
    /// <param name="virtual_path">The root virtual path for the mappings.</param>
    /// <param name="job">The job object associated with the mappings.</param>
    /// <param name="sid">The user SID associated with the mappings.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus RemoveMapping(string virtual_path, NtJob job, Sid sid, bool throw_on_error)
    {
        using var sid_buffer = sid?.ToSafeBuffer() ?? SafeSidBufferHandle.Null;
        return NativeMethods.BfRemoveMappingEx(job.GetHandle(), sid_buffer, virtual_path).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Remove a mapping.
    /// </summary>
    /// <param name="virtual_path">The root virtual path for the mappings.</param>
    /// <param name="job">The job object associated with the mappings.</param>
    /// <param name="sid">The user SID associated with the mappings.</param>
    public static void RemoveMapping(string virtual_path, NtJob job = null, Sid sid = null)
    {
        RemoveMapping(virtual_path, job, sid, true);
    }

    /// <summary>
    /// Get the current bind filter mappings for a volume.
    /// </summary>
    /// <param name="virtual_path">The root virtual path for the mappings.</param>
    /// <returns>The list of mappings.</returns>
    public static IReadOnlyList<BindFilterMapping> GetVolumeMappings(string virtual_path)
    {
        if (virtual_path is null)
        {
            throw new ArgumentNullException(nameof(virtual_path));
        }
        return GetMappings(BfGetMappingFlags.Volume, null, virtual_path, null);
    }

    /// <summary>
    /// Get the current bind filter mappings.
    /// </summary>
    /// <param name="flags">Flags for the query.</param>
    /// <param name="job">The job object associated with the mappings.</param>
    /// <param name="virtual_path">The root virtual path for the mappings.</param>
    /// <param name="sid">The user SID associated with the mappings.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of mappings.</returns>
    public static NtResult<IReadOnlyList<BindFilterMapping>> GetMappings(BfGetMappingFlags flags, NtJob job, string virtual_path, Sid sid, bool throw_on_error)
    {
        using var buffer = new SafeStructureInOutBuffer<BINDFLT_GET_MAPPINGS_INFO>(0, true);
        using var sid_buffer = sid?.ToSafeBuffer() ?? SafeSidBufferHandle.Null;
        int buffer_size = buffer.Length;
        NtStatus status = NativeMethods.BfGetMappings(flags, job.GetHandle(), virtual_path,
            sid_buffer, ref buffer_size, buffer);
        if (status.IsSuccess())
        {
            return Array.Empty<BindFilterMapping>().CreateResult<IReadOnlyList<BindFilterMapping>>();
        }
        else if (status.MapNtStatusToDosError() != Win32Error.ERROR_MORE_DATA)
        {
            return status.CreateResultFromError<IReadOnlyList<BindFilterMapping>>(throw_on_error);
        }
        buffer.Resize(buffer_size);
        return NativeMethods.BfGetMappings(flags, job.GetHandle(), virtual_path,
            sid_buffer, ref buffer_size, buffer).CreateResult(throw_on_error, () => ParseMappings(buffer));
    }

    /// <summary>
    /// Get the current bind filter mappings.
    /// </summary>
    /// <param name="flags">Flags for the query.</param>
    /// <param name="job">The job object associated with the mappings.</param>
    /// <param name="virtual_path">The root virtual path for the mappings.</param>
    /// <param name="sid">The user SID associated with the mappings.</param>
    /// <returns>The list of mappings.</returns>
    public static IReadOnlyList<BindFilterMapping> GetMappings(BfGetMappingFlags flags, NtJob job, string virtual_path, Sid sid)
    {
        return GetMappings(flags, job, virtual_path, sid, true).Result;
    }
    #endregion

    #region Private Members
    private static IReadOnlyList<BindFilterMapping> ParseMappings(SafeStructureInOutBuffer<BINDFLT_GET_MAPPINGS_INFO> buffer)
    {
        var result = buffer.Result;
        List<BindFilterMapping> mappings = new();
        var entries = buffer.Data.ReadArray<BINDFLT_GET_MAPPINGS_ENTRY>(0, result.MappingCount);
        foreach (var entry in entries)
        {
            string virt_root = buffer.ReadUnicodeString((ulong)entry.VirtRootOffset, entry.VirtRootLength / 2);
            var targets = buffer.ReadArray<BINDFLT_GET_MAPPINGS_TARGET_ENTRY>(entry.TargetEntriesOffset, entry.NumberOfTargets);
            mappings.Add(new BindFilterMapping(virt_root, entry.Flags, 
                targets.Select(t => buffer.ReadUnicodeString((ulong)t.TargetRootOffset, t.TargetRootLength / 2))));
        }

        return mappings.AsReadOnly();
    }
    #endregion
}
