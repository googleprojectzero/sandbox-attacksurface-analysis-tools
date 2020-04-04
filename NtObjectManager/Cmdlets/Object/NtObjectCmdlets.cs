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

using NtApiDotNet;
using NtApiDotNet.Win32;
using NtObjectManager.Provider;
using NtObjectManager.Utils;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Text;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// Base object cmdlet.
    /// </summary>
    public abstract class NtObjectBaseNoPathCmdlet : PSCmdlet, IDisposable
    {
        /// <summary>
        /// <para type="description">Object Attribute flags used during Open/Create calls.</para>
        /// </summary>
        [Parameter]
        [Alias("ObjectAttributes")]
        public AttributeFlags AttributesFlags { get; set; }

        /// <summary>
        /// <para type="description">Set to provide an explicit security descriptor to a newly created object.</para>
        /// </summary>
        [Parameter]
        public SecurityDescriptor SecurityDescriptor { get; set; }

        /// <summary>
        /// <para type="description">Set to mark the new handle as inheritable. Can be used with ObjectAttributes.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Inherit { get; set; }

        /// <summary>
        /// <para type="description">Set to provide an explicit security descriptor to a newly created object in SDDL format.</para>
        /// </summary>
        [Parameter]
        public string Sddl
        {
            get => SecurityDescriptor?.ToSddl();
            set => SecurityDescriptor = new SecurityDescriptor(value);
        }

        /// <summary>
        /// <para type="description">Set to provide an explicit security quality of service when opening files/namedpipes.</para>
        /// </summary>
        [Parameter]
        public SecurityQualityOfService SecurityQualityOfService { get; set; }

        /// <summary>
        /// Base constructor.
        /// </summary>
        protected NtObjectBaseNoPathCmdlet()
        {
            AttributesFlags = AttributeFlags.CaseInsensitive;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected abstract object CreateObject(ObjectAttributes obj_attributes);

        /// <summary>
        /// Create object from components.
        /// </summary>
        /// <param name="path">The path to the object.</param>
        /// <param name="attributes">The object attributes.</param>
        /// <param name="root">The root object.</param>
        /// <param name="security_quality_of_service">Security quality of service.</param>
        /// <param name="security_descriptor">Security descriptor.</param>
        /// <returns>The created object.</returns>
        protected object CreateObject(string path, AttributeFlags attributes, NtObject root, 
            SecurityQualityOfService security_quality_of_service, SecurityDescriptor security_descriptor)
        {
            if (Inherit)
            {
                attributes |= AttributeFlags.Inherit;
            }
            using (ObjectAttributes obja = new ObjectAttributes(path, attributes, root, 
                security_quality_of_service, security_descriptor))
            {
                return CreateObject(obja);
            }
        }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            WriteObject(CreateObject(null, AttributesFlags, null, SecurityQualityOfService, SecurityDescriptor), true);
        }

        #region IDisposable Support
        /// <summary>
        /// Dispose object.
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
        }

        /// <summary>
        /// Finalizer.
        /// </summary>
        ~NtObjectBaseNoPathCmdlet()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose object.
        /// </summary>
        void IDisposable.Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }

    /// <summary>
    /// Base object cmdlet.
    /// </summary>
    public abstract class NtObjectBaseCmdlet : NtObjectBaseNoPathCmdlet
    {
        /// <summary>
        /// <para type="description">The NT object manager path to the object to use.</para>
        /// </summary>
        [Parameter(Position = 0)]
        public virtual string Path { get; set; }

        /// <summary>
        /// <para type="description">An existing open NT object to use when Path is relative.</para>
        /// </summary>
        [Parameter(ValueFromPipeline = true)]
        public NtObject Root { get; set; }

        /// <summary>
        /// <para type="description">Use a Win32 path for lookups. For NT objects this means relative to BNO, for files means a DOS style path.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Win32Path { get; set; }

        /// <summary>
        /// <para type="description">Automatically close the Root object when this cmdlet finishes processing. Useful for pipelines.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter CloseRoot { get; set; }

        /// <summary>
        /// <para type="description">Create any necessary NtDirectory objects to create the required object. Will return the created directories as well as the object in the output.
        /// The new object will be the first entry in the list. This doesn't work when opening an object or creating keys/files.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter CreateDirectories { get; set; }
        
        /// <summary>
        /// Base constructor.
        /// </summary>
        protected NtObjectBaseCmdlet()
        {
        }

        /// <summary>
        /// Verify the parameters, should throw an exception if parameters are invalid.
        /// </summary>
        protected virtual void VerifyParameters()
        {
            string path = ResolvePath();
            if (path != null)
            {
                if (!path.StartsWith(@"\") && Root == null)
                {
                    throw new ArgumentException("Relative paths with no Root directory are not allowed.");
                }
            }

            if (Win32Path && Root != null)
            {
                throw new ArgumentException("Can't combine Win32Path and Root");
            }

            if (CreateDirectories)
            {
                if (!CanCreateDirectories())
                {
                    throw new ArgumentException("Can't specify CreateDirectories when opening an object.");
                }

                if (Root != null && !(Root is NtDirectory))
                {
                    throw new ArgumentException("Can't specify CreateDirectories when Root is not a directory.");
                }
            }
        }

        private static string RemoveDrive(string path)
        {
            int index = path.IndexOf(@":\");
            if (index < 0)
            {
                throw new ArgumentException("Invalid drive path");
            }
            return path.Substring(index + 2);
        }

        /// <summary>
        /// Get the Win32 path for a specified path.
        /// </summary>
        /// <param name="path">The path component.</param>
        /// <returns>The full NT path.</returns>
        protected virtual string GetWin32Path(string path)
        {
            return $@"{NtDirectory.GetBasedNamedObjects()}\{path}";
        }

        /// <summary>
        /// Virtual method to resolve the value of the Path variable.
        /// </summary>
        /// <returns>The object path.</returns>
        protected virtual string ResolvePath()
        {
            if (Path == null)
            {
                return null;
            }

            if (Win32Path)
            {
                if (Path.StartsWith(@"\"))
                {
                    throw new ArgumentException("Win32 paths can't start with a path separator");
                }

                return GetWin32Path(Path);
            }

            if (Path.StartsWith(@"\") || Root != null)
            {
                return Path;
            }

            var current_path = SessionState.Path.CurrentLocation;
            if (current_path.Drive is ObjectManagerPSDriveInfo drive)
            {
                string root_path = drive.DirectoryRoot.FullPath;
                if (root_path == @"\")
                {
                    root_path = string.Empty;
                }

                string relative_path = RemoveDrive(current_path.Path);
                if (relative_path.Length == 0)
                {
                    return $@"{root_path}\{Path}";
                }
                return $@"{root_path}\{relative_path}\{Path}";
            }
            else
            {
                throw new ArgumentException("Can't make a relative object path when not in a NtObject drive.");
            }
        }


        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected abstract bool CanCreateDirectories();

        private IEnumerable<NtObject> CreateDirectoriesAndObject()
        {
            DisposableList<NtObject> objects = new DisposableList<NtObject>();
            string[] path_parts = ResolvePath().Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            StringBuilder builder = new StringBuilder();
            bool finished = false;
            if (Root == null)
            {
                builder.Append(@"\");
            }

            try
            {
                for (int i = 0; i < path_parts.Length - 1; ++i)
                {
                    builder.Append(path_parts[i]);
                    NtDirectory dir = null;
                    try
                    {
                        dir = NtDirectory.Create(builder.ToString(), Root, DirectoryAccessRights.MaximumAllowed);
                    }
                    catch (NtException)
                    {
                    }

                    if (dir != null)
                    {
                        objects.Add(dir);
                    }
                    builder.Append(@"\");
                }
                objects.Add((NtObject)CreateObject(ResolvePath(), AttributesFlags, Root, SecurityQualityOfService, SecurityDescriptor));
                finished = true;
            }
            finally
            {
                if (!finished)
                {
                    objects.Dispose();
                    objects.Clear();
                }
            }
            return objects.ToArray();
        }
        
        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            VerifyParameters();
            try
            {
                WriteObject(CreateObject(ResolvePath(), AttributesFlags, Root, SecurityQualityOfService, SecurityDescriptor), true);
            }
            catch (NtException ex)
            {
                if (ex.Status != NtStatus.STATUS_OBJECT_PATH_NOT_FOUND || !CreateDirectories)
                {
                    throw;
                }

                WriteObject(CreateDirectoriesAndObject().Reverse(), true);
            }
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        /// <summary>
        /// Dispose object.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (CloseRoot && Root != null)
                {
                    NtObject obj = Root;
                    Root = null;
                    obj.Close();
                }
                disposedValue = true;
            }
        }

        #endregion
    }

    /// <summary>
    /// Base object cmdlet which has an access parameter.
    /// </summary>
    /// <typeparam name="T">The access enumeration type.</typeparam>
    public abstract class NtObjectBaseNoPathCmdletWithAccess<T> : NtObjectBaseNoPathCmdlet where T : Enum
    {
        /// <summary>
        /// <para type="description">Specify the access rights for a new handle when creating/opening an object.</para>
        /// </summary>
        [Parameter]
        public T Access { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        protected NtObjectBaseNoPathCmdletWithAccess()
        {
            Access = (T)Enum.ToObject(typeof(T), (uint)GenericAccessRights.MaximumAllowed);
        }
    }

    /// <summary>
    /// Base object cmdlet which has an access parameter.
    /// </summary>
    /// <typeparam name="T">The access enumeration type.</typeparam>
    public abstract class NtObjectBaseCmdletWithAccess<T> : NtObjectBaseCmdlet where T : Enum
    {
        /// <summary>
        /// <para type="description">Specify the access rights for a new handle when creating/opening an object.</para>
        /// </summary>
        [Parameter]
        public T Access { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        protected NtObjectBaseCmdletWithAccess()
        {
            Access = (T)Enum.ToObject(typeof(T), (uint)GenericAccessRights.MaximumAllowed);
        }
    }

    /// <summary>
    /// <para type="synopsis">Open an NT object by path.</para>
    /// <para type="description">This cmdlet opens an NT object by its path. The returned object
    /// will be a type specific to the actual underlying NT type.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtObject \BaseNamedObjects\ABC</code>
    ///   <para>Get a existing object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtObject \BaseNamedObjects -TypeName Directory</code>
    ///   <para>Get a existing object with an explicit type.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtObject \BaseNamedObjects&#x0A;$obj = Get-NtObject ABC -Root $root</code>
    ///   <para>Get an existing object with a relative path.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtObject")]
    [OutputType(typeof(NtObject))]
    public sealed class GetNtObjectCmdlet : NtObjectBaseCmdletWithAccess<GenericAccessRights>
    {
        /// <summary>
        /// <para type="description">The type of object will try and be determined automatically, however in cases where this isn't possible the NT type name can be specified here.
        /// This needs to be a value such as Directory, SymbolicLink, Mutant etc.
        /// </para>
        /// </summary>
        [Parameter]
        public string TypeName { get; set; }

        /// <summary>
        /// <para type="description">The NT object manager path to the object to use.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public override string Path { get; set; }

        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected override bool CanCreateDirectories()
        {
            return false;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            string type_name = string.IsNullOrWhiteSpace(TypeName) ? null : TypeName;
            return NtObject.OpenWithType(type_name, ResolvePath(), Root, AttributesFlags, Access, SecurityQualityOfService);
        }
    }

    /// <summary>
    /// <para type="synopsis">Use an NtObject (or list of NtObject) and automatically close the objects after use.</para>
    /// <para type="description">This cmdlet allows you to scope the use of NtObject, similar to the using statement in C#.
    /// When the script block passed to this cmdlet goes out of scope the input object is automatically disposed of, ensuring
    /// any native resources are closed to prevent leaks.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>$ps = Use-NtObject (Get-NtProcess) { param ($ps); $ps | Select-Object Name, CommandLine }</code>
    ///   <para>Select Name and CommandLine from a list of processes and dispose of the list afterwards.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsOther.Use, "NtObject")]
    public sealed class UseNtObjectCmdlet : Cmdlet, IDisposable
    {
        /// <summary>
        /// <para type="description">Specify the input object to be disposed.</para>
        /// </summary>
        [Parameter(Mandatory = true, ValueFromPipeline = true, Position = 0)]
        [AllowNull]
        public object InputObject { get; set; }

        /// <summary>
        /// <para type="description">Specify the script block to execute.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 1)]
        public ScriptBlock ScriptBlock { get; set; }

        /// <summary>
        /// Overridden process record method
        /// </summary>
        protected override void ProcessRecord()
        {
            WriteObject(ScriptBlock.InvokeWithArg(InputObject), true);
        }

        private static void DisposeObject(object obj)
        {
            IDisposable disp = obj as IDisposable;
            if (obj is PSObject psobj)
            {
                disp = psobj.BaseObject as IDisposable;
            }

            if (disp != null)
            {
                disp.Dispose();
            }
        }

        void IDisposable.Dispose()
        {
            if (InputObject is IEnumerable e)
            {
                foreach (object obj in e)
                {
                    DisposeObject(obj);
                }
            }
            else
            {
                DisposeObject(InputObject);
            }
        }
    }

    /// <summary>
    /// The result of an NTSTATUS code lookup.
    /// </summary>
    public sealed class NtStatusResult
    {
        /// <summary>
        /// The numeric value of the status code.
        /// </summary>
        public uint Status { get; }
        /// <summary>
        /// The numeric value of the status code as a signed integer.
        /// </summary>
        public int StatusSigned => (int)Status;
        /// <summary>
        /// The name of the status code if known.
        /// </summary>
        public string StatusName { get; }
        /// <summary>
        /// Corresponding message text.
        /// </summary>
        public string Message { get; }
        /// <summary>
        /// Win32 error code.
        /// </summary>
        public Win32Error Win32Error { get; }
        /// <summary>
        /// Win32 error as an integer.
        /// </summary>
        public int Win32ErrorCode => (int)Win32Error;
        /// <summary>
        /// The status code.
        /// </summary>
        public int Code { get; }
        /// <summary>
        /// True if a customer code.
        /// </summary>
        public bool CustomerCode { get; }
        /// <summary>
        /// True if reserved.
        /// </summary>
        public bool Reserved { get; }
        /// <summary>
        /// The status facility.
        /// </summary>
        public NtStatusFacility Facility { get; }
        /// <summary>
        /// The status severity.
        /// </summary>
        public NtStatusSeverity Severity { get; }

        internal NtStatusResult(NtStatus status)
        {
            Status = (uint)status;

            Message = NtObjectUtils.GetNtStatusMessage(status);
            Win32Error = NtObjectUtils.MapNtStatusToDosError(status);
            StatusName = status.ToString();
            Code = status.GetStatusCode();
            CustomerCode = status.IsCustomerCode();
            Reserved = status.IsReserved();
            Facility = status.GetFacility();
            Severity = status.GetSeverity();
        }

        internal NtStatusResult(int status) 
            : this(NtObjectUtils.ConvertIntToNtStatus(status))
        {
        }
    }

    /// <summary>
    /// <para type="synopsis">Get known information about an NTSTATUS code.</para>
    /// <para type="description">This cmdlet looks up an NTSTATUS code and if possible prints the
    /// enumeration name, the message description and the corresponding win32 error.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Get-NtStatus</code>
    ///   <para>Gets all known NTSTATUS codes defined in this library.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtStatus -Status 0xc0000022</code>
    ///   <para>Gets information about a specific status code.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtStatus", DefaultParameterSetName = "All")]
    public sealed class GetNtStatusCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify a NTSTATUS code to retrieve.</para>
        /// </summary>
        [Parameter(Position = 0, ParameterSetName = "FromStatus")]
        public int Status { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (ParameterSetName == "FromStatus")
            {
                WriteObject(new NtStatusResult(Status));
            }
            else
            {
                WriteObject(Enum.GetValues(typeof(NtStatus)).Cast<NtStatus>().Distinct().Select(s => new NtStatusResult(s)), true);
            }
        }
    }

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
    ///   <code>Copy-NtObject -Handle 1234 -SourceProcess $proc</code>
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
            using (var dup_obj = NtGeneric.DuplicateFrom(SourceProcess, handle, 
                GetDesiredAccess(), ObjectAttributes ?? 0, GetOptions()))
            {
                return dup_obj.ToTypedObject();
            }
        }

        private object GetHandle(IntPtr handle)
        {
            return NtObject.DuplicateHandle(SourceProcess, handle, DestinationProcess, 
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

    /// <summary>
    /// Base class for child object visitor.
    /// </summary>
    /// <typeparam name="O">The type of NT object.</typeparam>
    /// <typeparam name="A">The access rights type.</typeparam>
    public abstract class BaseGetNtChildObjectCmdlet<O, A> : PSCmdlet where A : Enum where O : NtObject
    {
        /// <summary>
        /// <para type="description">Specify an object to get children from, should be a directory.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public O Object { get; set; }

        /// <summary>
        /// <para type="description">Specify the access when opening a child.</para>
        /// </summary>
        [Parameter]
        public A Access { get; set; }

        /// <summary>
        /// <para type="description">Get children recursively.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Recurse { get; set; }

        /// <summary>
        /// <para type="description">When recursing specify the maximum depth of recursion. -1 indicates no limit.</para>
        /// </summary>
        [Parameter]
        public int MaxDepth { get; set; }

        /// <summary>
        /// <para type="description">Specify a script block to run for every child. The file object will automatically 
        /// be disposed once the vistor has executed. If you want to cancel enumeration return $false.</para>
        /// </summary>
        [Parameter]
        public ScriptBlock Visitor { get; set; }

        /// <summary>
        /// <para type="description">Specify a script block to filter child objects. Return $true to keep the object.</para>
        /// </summary>
        [Parameter]
        public ScriptBlock Filter { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public BaseGetNtChildObjectCmdlet()
        {
            Access = (A)Enum.ToObject(typeof(A), (uint)GenericAccessRights.MaximumAllowed);
            MaxDepth = -1;
        }

        /// <summary>
        /// Function to visit child objects.
        /// </summary>
        /// <param name="visitor">The visitor function to execute.</param>
        /// <returns>True if visited all children, false if cancelled.</returns>
        protected abstract bool VisitChildObjects(Func<O, bool> visitor);

        private static bool? InvokeScriptBlock(ScriptBlock script_block, params object[] args)
        {
            if (script_block.InvokeWithArg<object>(null, args) is bool b)
            {
                return b;
            }
            return null;
        }

        private bool WriteObjectVisitor(O obj)
        {
            WriteObject(obj.DuplicateObject());
            return !Stopping;
        }

        private bool ScriptBlockVisitor(O obj)
        {
            bool? result = InvokeScriptBlock(Visitor, obj);
            if (result.HasValue)
            {
                return result.Value;
            }
            
            return !Stopping;
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            Func<O, bool> visitor;
            if (Visitor != null)
            {
                visitor = ScriptBlockVisitor;
            }
            else
            {
                visitor = WriteObjectVisitor;
            }

            if (Filter != null)
            {
                VisitChildObjects(o =>
                {
                    bool? result = InvokeScriptBlock(Filter, o);
                    if (result.HasValue && result.Value)
                    {
                        return visitor(o);
                    }
                    return !Stopping;
                });
            }
            else
            {
                VisitChildObjects(visitor);
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Call QueryInformation on the object type.</para>
    /// <para type="description">This cmdlet queries information from an object handle. You specify the information class by name or number.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Get-NtObjectInformation -Object $obj -InfoClass BasicInfo</code>
    ///   <para>Query the basic info class for the object.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtObjectInformation -Object $obj -InfoClass 1</code>
    ///   <para>Query the info class 1 for the object.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtObjectInformation -Object $obj -InfoClass BasicInfo -InitialBytes @(1, 2, 3, 4)</code>
    ///   <para>Query the basic info class providing an initial buffer as bytes.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtObjectInformation -Object $obj -InfoClass BasicInfo -InitialLength 16</code>
    ///   <para>Query the basic info class providing an initial 16 byte buffer.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtObjectInformation -Object $obj -InfoClass BasicInfo -QueryBuffer</code>
    ///   <para>Query the basic info class and return a safe buffer.</para>
    /// </example>
    /// /// <example>
    ///   <code>Get-NtObjectInformation -Object $obj -InfoClass BasicInfo -QueryType $type</code>
    ///   <para>Query the basic info class and a typed value. $type needs to be a blitable .NET type.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtObjectInformation", DefaultParameterSetName = "QueryBytes")]
    [OutputType(typeof(byte[]))]
    [OutputType(typeof(SafeBufferGeneric))]
    public sealed class GetNtObjectInfoCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the object to query information from.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public NtObject Object { get; set; }

        /// <summary>
        /// <para type="description">Specify the information class to query. Can be a string or an integer.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 1)]
        [ArgumentCompleter(typeof(QueryInfoClassCompleter))]
        public string InformationClass { get; set; }

        /// <summary>
        /// <para type="description">Return the result as a buffer rather than a byte array.</para>
        /// </summary>
        [Parameter(ParameterSetName = "QueryBuffer")]
        public SwitchParameter AsBuffer { get; set; }

        /// <summary>
        /// <para type="description">Return the result as a type rather than a byte array. Also uses type size for initial sizing.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Type")]
        public Type AsType { get; set; }

        /// <summary>
        /// <para type="description">Specify initial value as a byte array.</para>
        /// </summary>
        [Parameter]
        public byte[] InitBuffer { get; set; }

        /// <summary>
        /// <para type="description">Specify initial value as an empty buffer of a specified length.</para>
        /// </summary>
        [Parameter]
        public int Length { get; set; }

        private byte[] GetInitialBuffer()
        {
            if (InitBuffer != null)
            {
                return InitBuffer;
            }
            else if (AsType != null)
            {
                return new byte[Marshal.SizeOf(AsType)];
            }
            return new byte[Length];
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            INtObjectQueryInformation query_info = (INtObjectQueryInformation)Object;
            int info_class;
            if (Object.NtType.QueryInformationClass.ContainsKey(InformationClass))
            {
                info_class = Object.NtType.QueryInformationClass[InformationClass];
            }
            else if (!int.TryParse(InformationClass, out info_class))
            {
                throw new ArgumentException($"Invalid info class {InformationClass}");
            }

            using (var buffer = query_info.QueryBuffer(info_class, GetInitialBuffer(), true).Result)
            {
                if (AsBuffer)
                {
                    WriteObject(buffer.Detach());
                }
                else if (AsType != null)
                {
                    WriteObject(Marshal.PtrToStructure(buffer.DangerousGetHandle(), AsType));
                }
                else
                {
                    WriteObject(buffer.ToArray());
                }
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Call SetInformation on the object type.</para>
    /// <para type="description">This cmdlet sets information tyo an object handle. You specify the information class by name or number.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>Set-NtObjectInformation -Object $obj -InformationClass BasicInfo -Bytes @(1, 2, 3, 4)</code>
    ///   <para>Set the basic info class for the object.</para>
    /// </example>
    /// <example>
    ///   <code>Set-NtObjectInformation -Object $obj -InformationClass 1 -Bytes @(1, 2, 3, 4)</code>
    ///   <para>Query the info class 1 for the object.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Set, "NtObjectInformation", DefaultParameterSetName = "SetBytes")]
    public sealed class SetNtObjectInformationCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the object to set information to.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public NtObject Object { get; set; }

        /// <summary>
        /// <para type="description">Specify the information class to set. Can be a string or an integer.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 1)]
        [ArgumentCompleter(typeof(QueryInfoClassCompleter))]
        public string InformationClass { get; set; }

        /// <summary>
        /// <para type="description">Sets the buffer rather than a byte array.</para>
        /// </summary>
        [Parameter(ParameterSetName = "SetBytes")]
        public byte[] Bytes { get; set; }

        /// <summary>
        /// <para type="description">Sets the buffer rather than a byte array.</para>
        /// </summary>
        [Parameter(ParameterSetName = "SetBuffer")]
        public SafeBuffer Buffer { get; set; }

        /// <summary>
        /// <para type="description">Sets the information as a blittable value type.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Type")]
        public object Value { get; set; }

        private SafeBuffer GetInitialBuffer()
        {
            if (Buffer != null)
            {
                return new SafeHGlobalBuffer(Buffer.DangerousGetHandle(), (int)Buffer.ByteLength, false);
            }
            else if (Bytes != null)
            {
                return new SafeHGlobalBuffer(Bytes);
            }
            else
            {
                using (var buffer = new SafeHGlobalBuffer(Marshal.SizeOf(Value)))
                {
                    Marshal.StructureToPtr(Value, buffer.DangerousGetHandle(), false);
                    return buffer.Detach();
                }
            }
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            INtObjectSetInformation set_info = (INtObjectSetInformation)Object;
            int info_class;
            if (Object.NtType.SetInformationClass.ContainsKey(InformationClass))
            {
                info_class = Object.NtType.SetInformationClass[InformationClass];
            }
            else if (!int.TryParse(InformationClass, out info_class))
            {
                throw new ArgumentException($"Invalid info class {InformationClass}");
            }

            using (var buffer = GetInitialBuffer())
            {
                set_info.SetBuffer(info_class, buffer, true);
            }
        }
    }
}
