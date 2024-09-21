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

using NtCoreLib;
using NtCoreLib.Security.Authorization;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Duplicate an object to a new handle. Optionally specify processes to duplicate to.</para>
/// <para type="description">This cmdlet duplicates an object either in the same process or between processes. If you duplicate to another process the cmdlet will return a handle value rather than an object.
/// </para>
/// </summary>
/// <example>
///   <code>Copy-NtObject -Object $obj</code>
///   <para>Duplicate an object to another in the current process with same access rights.</para>
/// </example>
/// <example>
///   <code>Copy-NtObject -Object $obj -DestinationProcess $proc</code>
///   <para>Duplicate an object to another process. If the desintation process is the current process an object is returned, otherwise a handle is returned.</para>
/// </example>
/// <example>
///   <code>Copy-NtObject -SourceHandle 1234 -SourceProcess $proc</code>
///   <para>Duplicate an object from another process to the current process.</para>
/// </example>
[Cmdlet(VerbsCommon.Copy, "NtObject")]
[OutputType(typeof(NtObject))]
public sealed class CopyNtObjectCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the object to duplicate in the current process.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromObject", ValueFromPipeline = true)]
    public NtObject[] Object { get; set; }

    /// <summary>
    /// <para type="description">Specify the object to duplicate in the current process.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromNtHandle", ValueFromPipeline = true)]
    public NtHandle[] Handle { get; set; }

    /// <summary>
    /// <para type="description">Specify the object to duplicate as a handle.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromHandle")]
    public IntPtr[] SourceHandle { get; set; }

    /// <summary>
    /// <para type="description">Specify the process to duplicate from.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromHandle")]
    public NtProcess SourceProcess { get; set; }

    /// <summary>
    /// <para type="description">Specify the process to duplicate to. Defaults to current process.</para>
    /// </summary>
    [Parameter]
    public NtProcess DestinationProcess { get; set; }

    /// <summary>
    /// <para type="description">The desired access for the duplication.</para>
    /// </summary>
    [Parameter]
    public GenericAccessRights? DesiredAccess { get; set; }

    /// <summary>
    /// <para type="description">The desired access for the duplication as an access mask.</para>
    /// </summary>
    [Parameter]
    public AccessMask? DesiredAccessMask { get; set; }

    /// <summary>
    /// <para type="description">Specify the no rights upgrade flags.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter NoRightsUpgrade { get; set; }

    /// <summary>
    /// <para type="description">The desired object attribute flags for the duplication.</para>
    /// </summary>
    [Parameter]
    public AttributeFlags? ObjectAttributes { get; set; }

    /// <summary>
    /// <para type="description">Close the source handle.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromHandle")]
    public SwitchParameter CloseSource { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public CopyNtObjectCmdlet()
    {
        SourceProcess = NtProcess.Current;
        DestinationProcess = NtProcess.Current;
    }

    private DuplicateObjectOptions GetOptions()
    {
        DuplicateObjectOptions options = DuplicateObjectOptions.None;
        if (!DesiredAccess.HasValue && !DesiredAccessMask.HasValue)
        {
            options |= DuplicateObjectOptions.SameAccess;
        }

        if (!ObjectAttributes.HasValue)
        {
            options |= DuplicateObjectOptions.SameAttributes;
        }

        if (CloseSource)
        {
            options |= DuplicateObjectOptions.CloseSource;
        }

        if (NoRightsUpgrade)
        {
            options |= DuplicateObjectOptions.NoRightsUpgrade;
        }

        return options;
    }

    private GenericAccessRights GetDesiredAccess()
    {
        if (DesiredAccess.HasValue)
        {
            return DesiredAccess.Value;
        }
        if (DesiredAccessMask.HasValue)
        {
            return DesiredAccessMask.Value.ToGenericAccess();
        }
        return GenericAccessRights.None;
    }

    private object GetObject(IntPtr handle)
    {
        using var dup_obj = NtGeneric.DuplicateFrom(SourceProcess, handle,
            GetDesiredAccess(), ObjectAttributes ?? 0, GetOptions());
        return dup_obj.ToTypedObject();
    }

    private object GetHandle(IntPtr handle)
    {
        return NtObject.DuplicateHandle(SourceProcess, handle, DestinationProcess, 
            GetDesiredAccess(), ObjectAttributes ?? 0, GetOptions());
    }

    private object GetObject(NtHandle handle)
    {
        using var proc = NtProcess.Open(handle.ProcessId, ProcessAccessRights.DupHandle);
        using var dup_obj = NtGeneric.DuplicateFrom(proc, new IntPtr(handle.Handle),
            GetDesiredAccess(), ObjectAttributes ?? 0, GetOptions());
        return dup_obj.ToTypedObject();
    }

    private object GetHandle(NtHandle handle)
    {
        using var proc = NtProcess.Open(handle.ProcessId, ProcessAccessRights.DupHandle);
        return NtObject.DuplicateHandle(proc, new IntPtr(handle.Handle), DestinationProcess,
            GetDesiredAccess(), ObjectAttributes ?? 0, GetOptions());
    }

    private object GetObject(NtObject obj)
    {
        return obj.DuplicateObject(GetDesiredAccess(), ObjectAttributes ?? 0, GetOptions());
    }

    private object GetHandle(NtObject obj)
    {
        return GetHandle(obj.Handle.DangerousGetHandle());
    }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (ParameterSetName == "FromObject")
        {
            Func<NtObject, object> func;
            if (DestinationProcess.ProcessId == NtProcess.Current.ProcessId)
            {
                func = GetObject;
            }
            else
            {
                func = GetHandle;
            }

            foreach (var obj in Object)
            {
                WriteObject(func(obj));
            }
        }
        else if (ParameterSetName == "FromNtHandle")
        {
            Func<NtHandle, object> func;
            if (DestinationProcess.ProcessId == NtProcess.Current.ProcessId)
            {
                func = GetObject;
            }
            else
            {
                func = GetHandle;
            }

            foreach (var obj in Handle)
            {
                try
                {
                    WriteObject(func(obj));
                }
                catch (NtException ex)
                {
                    if (Handle.Length == 1)
                        throw;
                    WriteError(new ErrorRecord(ex, "Error", ErrorCategory.OpenError, obj));
                }
            }
        }
        else
        {
            Func<IntPtr, object> func;
            if (DestinationProcess.ProcessId == NtProcess.Current.ProcessId)
            {
                func = GetObject;
            }
            else
            {
                func = GetHandle;
            }

            foreach (var handle in SourceHandle)
            {
                WriteObject(func(handle));
            }
        }
    }
}
