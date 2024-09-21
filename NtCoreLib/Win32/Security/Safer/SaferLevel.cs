//  Copyright 2016 Google Inc. All Rights Reserved.
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

using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Win32.Security.Interop;
using System;

namespace NtCoreLib.Win32.Security.Safer;

/// <summary>
/// Class to represent a safer level.
/// </summary>
public sealed class SaferLevel : IDisposable
{
    #region Private Members
    private readonly SafeSaferLevelHandle _handle;

    private SaferLevel(SafeSaferLevelHandle handle)
    {
        _handle = handle;
    }
    #endregion

    #region Static Methods
    /// <summary>
    /// Create a safer level.
    /// </summary>
    /// <param name="scope">The scope for the safer level</param>
    /// <param name="level">The level.</param>
    /// <param name="flags">Create flags.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The safer level object.</returns>
    public static NtResult<SaferLevel> Create(SaferScopeId scope, SaferLevelId level, SaferCreateLevelFlags flags, bool throw_on_error)
    {
        return SecurityNativeMethods.SaferCreateLevel(scope, level, flags, 
            out SafeSaferLevelHandle handle, IntPtr.Zero).CreateWin32Result(throw_on_error, () => new SaferLevel(handle));
    }

    /// <summary>
    /// Create a safer level.
    /// </summary>
    /// <param name="scope">The scope for the safer level</param>
    /// <param name="level">The level.</param>
    /// <param name="flags">Create flags.</param>
    /// <returns>The safer level object.</returns>
    public static SaferLevel Create(SaferScopeId scope, SaferLevelId level, SaferCreateLevelFlags flags)
    {
        return Create(scope, level, flags, true).Result;
    }

    /// <summary>
    /// Open a safer level.
    /// </summary>
    /// <param name="scope">The scope for the safer level</param>
    /// <param name="level">The level.</param>
    /// <returns>The safer level object.</returns>
    public static SaferLevel Open(SaferScopeId scope, SaferLevelId level)
    {
        return Create(scope, level, SaferCreateLevelFlags.Open);
    }

    #endregion

    #region Public Methods
    /// <summary>
    /// Compute token for the level.
    /// </summary>
    /// <param name="token">The base token, can be null.</param>
    /// <param name="flags">Flags for computing the token.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The computed token.</returns>
    public NtResult<NtToken> ComputeToken(NtToken token, SaferComputeTokenFlags flags, bool throw_on_error)
    {
        return SecurityNativeMethods.SaferComputeTokenFromLevel(_handle,
            token?.Handle ?? SafeKernelObjectHandle.Null, 
            out SafeKernelObjectHandle handle, flags, IntPtr.Zero)
            .CreateWin32Result(throw_on_error, () => NtToken.FromHandle(handle));
    }

    /// <summary>
    /// Compute token for the level.
    /// </summary>
    /// <param name="token">The base token, can be null.</param>
    /// <param name="flags">Flags for computing the token.</param>
    /// <returns>The computed token.</returns>
    public NtToken ComputeToken(NtToken token, SaferComputeTokenFlags flags)
    {
        return ComputeToken(token, flags, true).Result;
    }

    /// <summary>
    /// Dispose of the safer level.
    /// </summary>
    public void Dispose()
    {
        _handle?.Dispose();
    }
    #endregion
}
