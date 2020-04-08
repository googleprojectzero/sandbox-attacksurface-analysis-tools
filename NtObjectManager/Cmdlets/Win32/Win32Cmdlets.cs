//  Copyright 2018 Google Inc. All Rights Reserved.
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

using NtApiDotNet;
using NtApiDotNet.Win32;
using NtApiDotNet.Win32.Security;
using System;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace NtObjectManager.Cmdlets.Win32
{
    /// <summary>
    /// <para type="synopsis">Create a DOS device symlink.</para>
    /// <para type="description">This cmdlet creates or redefines a DOS device symlink. This symlink will be permanent, until it's deleted rather than requiring a handle to be maintained.</para>
    /// </summary>
    /// <example>
    ///   <code>Add-DosDevice Z: C:\Windows</code>
    ///   <para>Define a Z: drive which points to C:\Windows.</para>
    /// </example>
    /// <example>
    ///   <code>Add-DosDevice Z: \Device\HarddiskVolume1\windows -RawTargetPath</code>
    ///   <para>Define a Z: drive which points to Windows using a raw target path.</para>
    /// </example>
    /// <example>
    ///   <code>Add-DosDevice "\RPC Control\ABC" c:\Windows</code>
    ///   <para>Define the symlink '\RPC Control\ABC' drive which points to c:\Windows.</para>
    /// </example>
    /// <example>
    ///   <code>Add-DosDevice Z: C:\Windows -NoBroadcastSystem</code>
    ///   <para>Define a Z: drive which points to C:\Windows but don't broadcast the changes to applications on the desktop.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Add, "DosDevice")]
    public class AddDosDeviceCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">The device name to create. If this string starts with a \ then the 
        /// symlink will be created relative to the root of the object manager.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public string DeviceName { get; set; }
        /// <summary>
        /// <para type="description">Specify the target path. This should be a DOS path, 
        /// unless RawTargetPath is set then it can be arbitrary object manager path.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 1)]
        public string TargetPath { get; set; }
        /// <summary>
        /// <para type="description">Don't broadcast the change to the desktop using WM_SETTINGCHANGE.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter NoBroadcastSystem { get; set; }
        /// <summary>
        /// <para type="description">Specify the TargetPath as a raw object manager path.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter RawTargetPath { get; set; }

        /// <summary>
        /// Overridden ProcessRecord.
        /// </summary>
        protected override void ProcessRecord()
        {
            DefineDosDeviceFlags flags = DefineDosDeviceFlags.None;
            if (NoBroadcastSystem)
            {
                flags |= DefineDosDeviceFlags.NoBroadcastSystem;
            }
            if (RawTargetPath)
            {
                flags |= DefineDosDeviceFlags.RawTargetPath;
            }

            string device_path = ConvertDevicePath(DeviceName);
            Win32Utils.DefineDosDevice(flags, device_path, TargetPath);
        }

        internal static string ConvertDevicePath(string device_path)
        {
            if (device_path.StartsWith(@"\"))
            {
                return @"Global\GLOBALROOT" + device_path;
            }
            return device_path;
        }
    }

    /// <summary>
    /// <para type="synopsis">Remove a DOS device symlink.</para>
    /// <para type="description">This cmdlet removes a DOS device symlink.</para>
    /// </summary>
    /// <example>
    ///   <code>Remove-DosDevice Z:</code>
    ///   <para>Remove the Z: drive.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-DosDevice Z: \Device\HarddiskVolume1\windows -RawTargetPath</code>
    ///   <para>Remove the Z: drive, which must point to \Device\HarddiskVolume1\Windows.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-DosDevice Z: c:\windows</code>
    ///   <para>Remove the Z: drive, which must point to c:\Windows.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-DosDevice "\RPC Control\ABC"</code>
    ///   <para>Remove '\RPC Control\ABC' symlink.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Remove, "DosDevice")]
    public class RemoveDosDeviceCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">The device name to create. If this string starts with a \ then the 
        /// symlink will be created relative to the root of the object manager.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public string DeviceName { get; set; }
        /// <summary>
        /// <para type="description">Specify an exact target path to remove. If the symlink doesn't match this target then it will not be removed.</para>
        /// </summary>
        [Parameter(Position = 1)]
        public string ExactMatchTargetPath { get; set; }
        /// <summary>
        /// <para type="description">Don't broadcast the change to the desktop using WM_SETTINGCHANGE.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter NoBroadcastSystem { get; set; }
        /// <summary>
        /// <para type="description">Specify the TargetPath as a raw object manager path.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter RawTargetPath { get; set; }

        /// <summary>
        /// Overridden ProcessRecord.
        /// </summary>
        protected override void ProcessRecord()
        {
            DefineDosDeviceFlags flags = DefineDosDeviceFlags.RemoveDefinition;
            if (NoBroadcastSystem)
            {
                flags |= DefineDosDeviceFlags.NoBroadcastSystem;
            }
            if (RawTargetPath)
            {
                flags |= DefineDosDeviceFlags.RawTargetPath;
            }
            if (!string.IsNullOrEmpty(ExactMatchTargetPath))
            {
                flags |= DefineDosDeviceFlags.ExactMatchOnRemove;
            }

            string device_path = AddDosDeviceCmdlet.ConvertDevicePath(DeviceName);

            Win32Utils.DefineDosDevice(flags, device_path, string.IsNullOrEmpty(ExactMatchTargetPath) ? null : ExactMatchTargetPath);
        }
    }

    /// <summary>
    /// The result of an WIN32 error code lookup.
    /// </summary>
    public sealed class Win32ErrorResult
    {
        /// <summary>
        /// The numeric value of the error code.
        /// </summary>
        public int ErrorCode { get; }
        /// <summary>
        /// The name of the error code if known.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Corresponding message text.
        /// </summary>
        public string Message { get; }

        internal Win32ErrorResult(Win32Error win32_error)
        {
            ErrorCode = (int)win32_error;
            Message = NtObjectUtils.GetNtStatusMessage(win32_error.MapDosErrorToStatus());
            Name = win32_error.ToString();
        }
    }

    /// <summary>
    /// <para type="synopsis">Get known information about a WIN32 error code.</para>
    /// <para type="description">This cmdlet looks up an WIN32 error code and if possible prints the
    /// enumeration name and the message description.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Get-Win32Error</code>
    ///   <para>Gets all known WIN32 error codes defined in this library.</para>
    /// </example>
    /// <example>
    ///   <code>Get-Win32Error -Error 5</code>
    ///   <para>Gets information about a specific WIN32 error code.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "Win32Error", DefaultParameterSetName = "All")]
    public sealed class GetWin32ErrorCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify a WIN32 error code to retrieve.</para>
        /// </summary>
        [Parameter(Position = 0, ParameterSetName = "FromError")]
        public int Error { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (ParameterSetName == "FromError")
            {
                WriteObject(new Win32ErrorResult((Win32Error)Error));
            }
            else
            {
                WriteObject(Enum.GetValues(typeof(Win32Error)).Cast<Win32Error>()
                    .Distinct().Select(e => new Win32ErrorResult(e)), true);
            }
        }
    }

    /// <summary>
    /// <para type="description">Result object for setting a security descriptor.</para>
    /// </summary>
    public class Win32SetSecurityDescriptorResult
    {
        /// <summary>
        /// The name of the resource which was set.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The error during the operation.
        /// </summary>
        public Win32Error Error { get; }
        /// <summary>
        /// Whether security was set.
        /// </summary>
        public bool SecuritySet { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="name">The name of the resource which was set.</param>
        /// <param name="error">The error during the operation.</param>
        /// <param name="security_set">Whether security was set.</param>
        internal Win32SetSecurityDescriptorResult(string name, Win32Error error, bool security_set)
        {
            Name = name;
            Error = error;
            SecuritySet = security_set;
        }
    }

    /// <summary>
    /// <para type="synopsis">Sets a security descriptor using the Win32 APIs.</para>
    /// <para type="description">This cmdlet sets the security descriptor on an object using the Win32 SetSecurityInfo APIs.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Set-Win32SecurityDescriptor "c:\test" $sd Dacl</code>
    ///   <para>Set the DACL of the file path c:\test.</para>
    /// </example>
    /// <example>
    ///   <code>Set-Win32SecurityDescriptor -Object $obj -Type Kernel $sd Dacl</code>
    ///   <para>Set the DACL of a kernel object.</para>
    /// </example>
    /// <example>
    ///   <code>Set-Win32SecurityDescriptor -Handle -Type Kernel $handle $sd Dacl</code>
    ///   <para>Set the DACL of a kernel object handle.</para>
    /// </example>
    /// <example>
    ///   <code>Set-Win32SecurityDescriptor "c:\test" $sd Dacl -ShowProgress</code>
    ///   <para>Set the DACL of the file path c:\test and show progress</para>
    /// </example>
    /// <example>
    ///   <code>Set-Win32SecurityDescriptor "c:\test"  $sd Dacl -ShowProgress</code>
    ///   <para>Set the DACL of the file path c:\test and show progress</para>
    /// </example>
    
    [Cmdlet(VerbsCommon.Set, "Win32SecurityDescriptor", DefaultParameterSetName = "FromName")]
    [OutputType(typeof(Win32SetSecurityDescriptorResult))]
    public sealed class SetWin32SecurityDescriptor : PSCmdlet
    {
        /// <summary>
        /// <para type="description">The name of the object.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromName")]
        public string Name { get; set; }

        /// <summary>
        /// <para type="description">Handle to an object.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromObject")]
        public NtObject Object { get; set; }

        /// <summary>
        /// <para type="description">Handle to an object.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromHandle")]
        public SafeHandle Handle { get; set; }

        /// <summary>
        /// <para type="description">The type of object represented by Name/Object/Handle. Default is File.</para>
        /// </summary>
        [Parameter]
        public SeObjectType Type { get; set; }

        /// <summary>
        /// <para type="description">The security descriptor to set.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true)]
        public SecurityDescriptor SecurityDescriptor { get; set; }

        /// <summary>
        /// <para type="description">Specify the security information to set.</para>
        /// </summary>
        [Parameter(Position = 2, Mandatory = true)]
        public SecurityInformation SecurityInformation { get; set; }

        /// <summary>
        /// <para type="description">Specify to show the progress when setting security.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromName")]
        public SwitchParameter ShowProgress { get; set; }

        /// <summary>
        /// <para type="description">Specify to pass through results of the security setting operation.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromName")]
        public SwitchParameter PassThru { get; set; }

        /// <summary>
        /// <para type="description">Specify to the tree operation to perform.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromName")]
        public TreeSecInfo Action { get; set; }

        /// <summary>
        /// <para type="description">Specify to only show progress/pass through when an error occurs.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromName")]
        public SwitchParameter ErrorOnly { get; set; }

        private ProgressInvokeSetting ProgressFunction(
            string object_name, Win32Error status, ProgressInvokeSetting invoke_setting, bool security_set)
        {
            if (Stopping)
            {
                return ProgressInvokeSetting.CancelOperation;
            }

            if (ErrorOnly && status == Win32Error.SUCCESS)
            {
                return invoke_setting;
            }

            if (ShowProgress)
            {
                ProgressRecord progress = new ProgressRecord(0, "Changing Security", object_name);
                WriteProgress(progress);
            }

            if (PassThru)
            {
                WriteObject(new Win32SetSecurityDescriptorResult(object_name, status, security_set));
            }

            return invoke_setting;
        }

        private void SetNamedSecurityInfo()
        {
            bool do_callback = ShowProgress || PassThru;

            if (do_callback || Action != TreeSecInfo.Set)
            {
                TreeProgressFunction fn = ProgressFunction;
                NtStatus status = Win32Security.SetSecurityInfo(Name, Type, SecurityInformation, SecurityDescriptor, Action, do_callback ? fn : null, 
                    ShowProgress ? ProgressInvokeSetting.PrePostError : ProgressInvokeSetting.EveryObject, !PassThru);
                if (!PassThru)
                {
                    status.ToNtException();
                }
            }
            else
            {
                Win32Security.SetSecurityInfo(Name, Type, SecurityInformation, SecurityDescriptor);
            }
        }

        /// <summary>
        /// Process Record.
        /// </summary>
        protected override void ProcessRecord()
        {
            switch (ParameterSetName)
            {
                case "FromName":
                    SetNamedSecurityInfo();
                    break;
                case "FromObject":
                    Win32Security.SetSecurityInfo(Object, Type, SecurityInformation, SecurityDescriptor);
                    break;
                case "FromHandle":
                    Win32Security.SetSecurityInfo(Handle, Type, SecurityInformation, SecurityDescriptor);
                    break;
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public SetWin32SecurityDescriptor()
        {
            Action = TreeSecInfo.Set;
            Type = SeObjectType.File;
        }
    }

    /// <summary>
    /// <para type="synopsis">Resets a security descriptor using the Win32 APIs.</para>
    /// <para type="description">This cmdlet resets the security descriptor on an object using the Win32 SetSecurityInfo APIs.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Reset-Win32SecurityDescriptor "c:\test" $sd Dacl</code>
    ///   <para>Reset the DACL of the file path c:\test.</para>
    /// </example>
    /// <example>
    ///   <code>Reset-Win32SecurityDescriptor "c:\test" $sd Dacl -KeepExplicit</code>
    ///   <para>Reset the DACL of the file path c:\test keeping explicit ACEs.</para>
    /// </example>
    /// <example>
    ///   <code>Reset-Win32SecurityDescriptor "c:\test" $sd Dacl -ShowProgress</code>
    ///   <para>Reset the DACL of the file path c:\test and show progress</para>
    /// </example>
    [Cmdlet(VerbsCommon.Reset, "Win32SecurityDescriptor")]
    [OutputType(typeof(Win32SetSecurityDescriptorResult))]
    public sealed class ResetWin32SecurityDescriptor : PSCmdlet
    {
        /// <summary>
        /// <para type="description">The name of the object.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public string Name { get; set; }

        /// <summary>
        /// <para type="description">The security descriptor to set.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true)]
        public SecurityDescriptor SecurityDescriptor { get; set; }

        /// <summary>
        /// <para type="description">Specify the security information to set.</para>
        /// </summary>
        [Parameter(Position = 2, Mandatory = true)]
        public SecurityInformation SecurityInformation { get; set; }

        /// <summary>
        /// <para type="description">The type of object represented by Name. Default to File.</para>
        /// </summary>
        [Parameter]
        public SeObjectType Type { get; set; }

        /// <summary>
        /// <para type="description">Specify to show the progress when setting security.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter ShowProgress { get; set; }

        /// <summary>
        /// <para type="description">Specify to keep explicit ACEs.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter KeepExplicit { get; set; }

        /// <summary>
        /// <para type="description">Specify to pass through results of the security setting operation.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter PassThru { get; set; }

        /// <summary>
        /// <para type="description">Specify to only show progress/pass through when an error occurs.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter ErrorOnly { get; set; }

        private ProgressInvokeSetting ProgressFunction(
            string object_name, Win32Error status, ProgressInvokeSetting invoke_setting, bool security_set)
        {
            if (Stopping)
            {
                return ProgressInvokeSetting.CancelOperation;
            }

            if (ErrorOnly && status == Win32Error.SUCCESS)
            {
                return invoke_setting;
            }

            if (ShowProgress)
            {
                ProgressRecord progress = new ProgressRecord(0, "Resetting Security", object_name);
                WriteProgress(progress);
            }

            if (PassThru)
            {
                WriteObject(new Win32SetSecurityDescriptorResult(object_name, status, security_set));
            }

            return invoke_setting;
        }

        /// <summary>
        /// Process Record.
        /// </summary>
        protected override void ProcessRecord()
        {
            bool do_callback = ShowProgress || PassThru;
            TreeProgressFunction fn = ProgressFunction;
            NtStatus status = Win32Security.ResetSecurityInfo(Name, Type, SecurityInformation, SecurityDescriptor, do_callback ? fn : null,
                ShowProgress ? ProgressInvokeSetting.PrePostError : ProgressInvokeSetting.EveryObject, KeepExplicit, !PassThru);
            if (!PassThru)
            {
                status.ToNtException();
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public ResetWin32SecurityDescriptor()
        {
            Type = SeObjectType.File;
        }
    }

    /// <summary>
    /// <para type="synopsis">Search for inherited ACLs for the security descriptor.</para>
    /// <para type="description">This cmdlet searches for the ancestors of an inherited security resource.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Search-Win32SecurityDescriptor "c:\test"</code>
    ///   <para>Search for the inheritance ancestors of c:\test.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Search, "Win32SecurityDescriptor")]
    [OutputType(typeof(SecurityDescriptorInheritanceSource))]
    public sealed class SearchWin32SecurityDescriptor : PSCmdlet
    {
        /// <summary>
        /// <para type="description">The name of the object.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public string Name { get; set; }

        /// <summary>
        /// <para type="description">The security descriptor to check for inheritance.</para>
        /// </summary>
        [Parameter]
        public SecurityDescriptor SecurityDescriptor { get; set; }

        /// <summary>
        /// <para type="description">Specify the GenericMapping for the check.</para>
        /// </summary>
        [Parameter]
        public GenericMapping? GenericMapping { get; set; }

        /// <summary>
        /// <para type="description">Specify to check the SACL. Default is the DACL.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Sacl { get; set; }

        /// <summary>
        /// <para type="description">The type of object represented by Name. Default is File.</para>
        /// </summary>
        [Parameter]
        public SeObjectType Type { get; set; }

        /// <summary>
        /// <para type="description">Specify list of object types.</para>
        /// </summary>
        [Parameter]
        public Guid[] ObjectType { get; set; }

        /// <summary>
        /// <para type="description">Specify to query the full security descriptor for the ancestors.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter QuerySecurity { get; set; }

        private GenericMapping GetGenericMapping()
        {
            if (GenericMapping.HasValue)
            {
                return GenericMapping.Value;
            }

            return Win32Security.GetNativeType(Type)?.GenericMapping 
                ?? throw new ArgumentException("Must specify a Generic Mapping for the type");
        }

        /// <summary>
        /// Process Record.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (SecurityDescriptor == null)
            {
                SecurityDescriptor = Win32Security.GetSecurityInfo(Name, Type, 
                    Sacl ? SecurityInformation.All : SecurityInformation.AllNoSacl);
            }

            WriteObject(Win32Security.GetInheritanceSource(Name, Type, IsContainer(), ObjectType,
                SecurityDescriptor, Sacl, GetGenericMapping(), QuerySecurity), true);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public SearchWin32SecurityDescriptor()
        {
            Type = SeObjectType.File;
        }

        private bool IsContainer()
        {
            if (Type == SeObjectType.File)
            {
                return Directory.Exists(Name);
            }
            return true;
        }
    }

    /// <summary>
    /// <para type="synopsis">Sets a security descriptor using the Win32 APIs.</para>
    /// <para type="description">This cmdlet sets the security descriptor on an object using the Win32 SetSecurityInfo APIs.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Get-Win32SecurityDescriptor "c:\test"</code>
    ///   <para>Set the security descriptor for file path c:\test.</para>
    /// </example>
    /// <example>
    ///   <code>Get-Win32SecurityDescriptor -Object $obj -Type Kernel Dacl</code>
    ///   <para>Get the DACL of a kernel object.</para>
    /// </example>
    /// <example>
    ///   <code>Get-Win32SecurityDescriptor -Handle -Type Kernel $handle Dacl</code>
    ///   <para>Get the DACL of a kernel object handle.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "Win32SecurityDescriptor", DefaultParameterSetName = "FromName")]
    [OutputType(typeof(SecurityDescriptor))]
    public sealed class GetWin32SecurityDescriptor : PSCmdlet
    {
        /// <summary>
        /// <para type="description">The name of the object.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromName")]
        public string Name { get; set; }

        /// <summary>
        /// <para type="description">Specify the security information to set.</para>
        /// </summary>
        [Parameter(Position = 1)]
        public SecurityInformation SecurityInformation { get; set; }

        /// <summary>
        /// <para type="description">Handle to an object.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromObject")]
        public NtObject Object { get; set; }

        /// <summary>
        /// <para type="description">Handle to an object.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromHandle")]
        public SafeHandle Handle { get; set; }

        /// <summary>
        /// <para type="description">The type of object represented by Name/Object/Handle. Default is File.</para>
        /// </summary>
        [Parameter]
        public SeObjectType Type { get; set; }

        /// <summary>
        /// Process Record.
        /// </summary>
        protected override void ProcessRecord()
        {
            SecurityDescriptor sd = null;
            switch (ParameterSetName)
            {
                case "FromName":
                    sd = Win32Security.GetSecurityInfo(Name, Type, SecurityInformation);
                    break;
                case "FromObject":
                    sd = Win32Security.GetSecurityInfo(Object.Handle, Type, SecurityInformation);
                    break;
                case "FromHandle":
                    sd = Win32Security.GetSecurityInfo(Handle, Type, SecurityInformation);
                    break;
            }
            if (sd != null)
            {
                WriteObject(sd);
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public GetWin32SecurityDescriptor()
        {
            Type = SeObjectType.File;
            SecurityInformation = SecurityInformation.AllBasic;
        }
    }
}
