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

using NtCoreLib;
using NtObjectManager.Utils;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// Base class for querying or setting a property on a file object.
/// </summary>
public abstract class BaseNtFilePropertyCmdlet : PSCmdlet
{
    private readonly FileAccessRights _desired_access;
    private readonly FileShareMode _share_mode;
    private readonly FileOpenOptions _options;

    /// <summary>
    /// <para type="description">Specify the file to use.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Default")]
    public NtFile File { get; set; }

    /// <summary>
    /// <para type="description">Specify the path to the file to use.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromPath")]
    public string Path { get; set; }

    /// <summary>
    /// <para type="description">Specify to specify the path as a Win32 path.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromPath")]
    public SwitchParameter Win32Path { get; set; }

    /// <summary>
    /// <para type="description">Specify to open the path case sensitively.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromPath")]
    public SwitchParameter CaseSensitive { get; set; }

    /// <summary>
    /// <para type="description">Specify to open the reparse point.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromPath")]
    public SwitchParameter OpenReparsePoint { get; set; }

    /// <summary>
    /// <para type="description">Specify to open the path with backup privileges.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromPath")]
    public SwitchParameter OpenForBackupIntent { get; set; }

    private protected abstract void HandleFile(NtFile file);

    private protected BaseNtFilePropertyCmdlet(FileAccessRights desired_access, FileShareMode share_mode, FileOpenOptions options)
    {
        _desired_access = desired_access;
        _share_mode = share_mode;
        _options = options;
    }

    /// <summary>
    /// Overridden process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (ParameterSetName == "Default")
        {
            HandleFile(File);
        }
        else
        {
            using var obja = new ObjectAttributes(PSUtils.ResolvePath(SessionState, Path, Win32Path),
                CaseSensitive ? AttributeFlags.None : AttributeFlags.CaseInsensitive);
            var opts = _options;
            if (OpenReparsePoint)
                opts |= FileOpenOptions.OpenReparsePoint;
            if (OpenForBackupIntent)
                opts |= FileOpenOptions.OpenForBackupIntent;
            using var file = NtFile.Open(obja, _desired_access, _share_mode, opts);
            HandleFile(file);
        }
    }
}
