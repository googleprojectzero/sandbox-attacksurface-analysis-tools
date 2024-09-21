//  Copyright 2023 Google LLC. All Rights Reserved.
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

using NtCoreLib.Image;
using NtCoreLib.Win32.SideBySide.Interop;
using NtCoreLib.Win32.SideBySide.Parser;
using System;
using System.IO;

namespace NtCoreLib.Win32.SideBySide;

/// <summary>
/// Class to represent a loaded activation context.
/// </summary>
public sealed class ActivationContext : IDisposable
{
    #region Private Members
    private readonly SafeActivationContextHandle _actctx;

    private ActivationContext(SafeActivationContextHandle actctx)
    {
        _actctx = actctx;
    }

    private static NtResult<ActivationContext> FromContext(ACTCTX ctx, bool throw_on_error)
    {
        return NativeMethods.CreateActCtx(ctx).CreateWin32Result(throw_on_error, h => new ActivationContext(h));
    }
    #endregion

    #region Static Methods
    /// <summary>
    /// Get the current activation context.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The activation context.</returns>
    public static NtResult<ActivationContext> GetCurrent(bool throw_on_error)
    {
        return NativeMethods.GetCurrentActCtx(out SafeActivationContextHandle actctx)
            .CreateWin32Result(throw_on_error, () => new ActivationContext(actctx));
    }

    /// <summary>
    /// Get the current activation context.
    /// </summary>
    /// <returns>The activation context.</returns>
    public static ActivationContext GetCurrent()
    {
        return GetCurrent(true).Result;
    }

    /// <summary>
    /// Create activation context from a file.
    /// </summary>
    /// <param name="path">Path to the manifest or PE file.</param>
    /// <param name="resource_id">Optional resource ID for the manifest if a PE file.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The activation context.</returns>
    public static NtResult<ActivationContext> FromFile(string path, ResourceString resource_id, bool throw_on_error)
    {
        resource_id ??= Path.GetExtension(path).ToLower() switch
            {
                ".exe" => new ResourceString(1),
                ".dll" => new ResourceString(2),
                _ => null,
            };
        using var resource_id_handle = resource_id?.ToHandle();
        return FromContext(new ACTCTX(path, resource_id_handle), throw_on_error);
    }

    /// <summary>
    /// Create activation context from a file.
    /// </summary>
    /// <param name="path">Path to the manifest or PE file.</param>
    /// <param name="resource_id">Optional resource ID for the manifest if a PE file.</param>
    /// <returns>The activation context.</returns>
    public static ActivationContext FromFile(string path, ResourceString resource_id = null)
    {
        return FromFile(path, resource_id, true).Result;
    }

    /// <summary>
    /// Create activation context from an assembly name.
    /// </summary>
    /// <param name="name">The assembly name.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The activation context.</returns>
    public static NtResult<ActivationContext> FromName(string name, bool throw_on_error)
    {
        ACTCTX ctx = new()
        {
            lpSource = name,
            dwFlags = ACTCTX_FLAG.ACTCTX_FLAG_SOURCE_IS_ASSEMBLYREF
        };
        return FromContext(ctx, throw_on_error);
    }

    /// <summary>
    /// Create activation context from an assembly name.
    /// </summary>
    /// <param name="name">The assembly name.</param>
    /// <returns>The activation context.</returns>
    public static ActivationContext FromName(string name)
    {
        return FromName(name, true).Result;
    }

    /// <summary>
    /// Create activation context from a configuration.
    /// </summary>
    /// <param name="config">The configuration to define the activation context.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The activation context.</returns>
    public static NtResult<ActivationContext> FromConfig(ActivationContextConfig config, bool throw_on_error)
    {
        ACTCTX ctx = new();
        ACTCTX_FLAG flags = 0;
        if (config.SetProcessDefault)
        {
            flags |= ACTCTX_FLAG.ACTCTX_FLAG_SET_PROCESS_DEFAULT;
        }
        if (config.SourceIsAssemblyRef)
        {
            flags |= ACTCTX_FLAG.ACTCTX_FLAG_SOURCE_IS_ASSEMBLYREF;
        }
        ctx.lpSource = config.Source;
        if (config.ApplicationName != null)
        {
            ctx.lpApplicationName = config.ApplicationName;
            flags |= ACTCTX_FLAG.ACTCTX_FLAG_APPLICATION_NAME_VALID;
        }
        if (config.LangId.HasValue)
        {
            ctx.wLangId = config.LangId.Value;
            flags |= ACTCTX_FLAG.ACTCTX_FLAG_LANGID_VALID;
        }
        if (config.ProcessorArchitecture.HasValue)
        {
            ctx.wProcessorArchitecture = (ushort)config.ProcessorArchitecture.Value;
            flags |= ACTCTX_FLAG.ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID;
        }
        using var resource_id_handle = config.ResourceName?.ToHandle();
        if (resource_id_handle != null)
        {
            ctx.lpResourceName = resource_id_handle.DangerousGetHandle();
            flags |= ACTCTX_FLAG.ACTCTX_FLAG_RESOURCE_NAME_VALID;
        }
        if (config.Module != null && !config.Module.IsInvalid)
        {
            ctx.hModule = config.Module.DangerousGetHandle();
            flags |= ACTCTX_FLAG.ACTCTX_FLAG_HMODULE_VALID;
        }
        if (config.AssemblyDirectory != null)
        {
            ctx.lpAssemblyDirectory = config.AssemblyDirectory;
            flags |= ACTCTX_FLAG.ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID;
        }
        ctx.dwFlags = flags;
        return FromContext(ctx, throw_on_error);
    }

    /// <summary>
    /// Create activation context from a configuration.
    /// </summary>
    /// <param name="config">The configuration to define the activation context.</param>
    /// <returns>The activation context.</returns>
    public static ActivationContext FromConfig(ActivationContextConfig config)
    {
        return FromConfig(config, true).Result;
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Activate the activation context on the current thread.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The activated activation context.</returns>
    public NtResult<ScopedActivationContext> Activate(bool throw_on_error)
    {
        return NativeMethods.ActivateActCtx(_actctx, out IntPtr cookie)
            .CreateWin32Result(throw_on_error, () => new ScopedActivationContext(cookie));
    }

    /// <summary>
    /// Activate the activation context on the current thread.
    /// </summary>
    /// <returns>The activated activation context.</returns>
    public ScopedActivationContext Activate()
    {
        return Activate(true).Result;
    }

    /// <summary>
    /// Parse the activation context data.
    /// </summary>
    /// <returns>The activation context data.</returns>
    public ActivationContextData Parse()
    {
        if (_actctx.IsInvalid || _actctx.IsClosed)
        {
            throw new ObjectDisposedException(nameof(_actctx));
        }

        long address;
        if (Environment.Is64BitProcess)
        {
            address = NtProcess.Current.ReadMemory<long>(_actctx.DangerousGetHandle().ToInt64() + 0x18);
        }
        else
        {
            address = NtProcess.Current.ReadMemory<uint>(_actctx.DangerousGetHandle().ToInt64() + 0x10);
        }

        return ActivationContextData.FromProcess(NtProcess.Current, address);
    }

    /// <summary>
    /// Dispose of the activation context.
    /// </summary>
    public void Dispose()
    {
        _actctx.Dispose();
    }
    #endregion
}
