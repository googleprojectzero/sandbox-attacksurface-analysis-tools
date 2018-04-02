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
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;

namespace NtObjectManager
{
    /// <summary>
    /// Base object cmdlet.
    /// </summary>
    public abstract class NtObjectBaseCmdlet : PSCmdlet, IDisposable
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
        /// <para type="description">Object Attribute flags used during Open/Create calls.</para>
        /// </summary>
        [Parameter]
        public AttributeFlags ObjectAttributes { get; set; }

        /// <summary>
        /// <para type="description">Set to provide an explicit security descriptor to a newly created object.</para>
        /// </summary>
        [Parameter]
        public SecurityDescriptor SecurityDescriptor { get; set; }

        /// <summary>
        /// <para type="description">Set to provide an explicit security descriptor to a newly created object in SDDL format. Overriddes SecurityDescriptor.</para>
        /// </summary>
        [Parameter]
        public string Sddl { get; set; }

        /// <summary>
        /// <para type="description">Set to provide an explicit security quality of service when opening files/namedpipes.</para>
        /// </summary>
        [Parameter]
        public SecurityQualityOfService SecurityQualityOfService { get; set; }

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
            ObjectAttributes = AttributeFlags.CaseInsensitive;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected abstract object CreateObject(ObjectAttributes obj_attributes);

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

                List<string> ret = new List<string>();
                int session_id = NtProcess.Current.SessionId;
                if (session_id != 0)
                {
                    ret.Add("Sessions");
                    ret.Add(session_id.ToString());
                }
                ret.Add("BaseNamedObjects");
                if (!String.IsNullOrEmpty(Path))
                {
                    ret.AddRange(Path.Split('\\'));
                }
                return $@"\{String.Join(@"\", ret)}";
            }

            if (Path.StartsWith(@"\") || Root != null)
            {
                return Path;
            }

            var current_path = SessionState.Path.CurrentLocation;
            if (current_path.Drive is NtObjectManagerProvider.ObjectManagerPSDriveInfo drive)
            {
                string root_path = drive.DirectoryRoot.FullPath;
                if (root_path == @"\")
                {
                    root_path = String.Empty;
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

        private object DoCreateObject(string path, AttributeFlags attributes, NtObject root, SecurityQualityOfService security_quality_of_service, SecurityDescriptor security_descriptor)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, attributes, root, security_quality_of_service, security_descriptor))
            {
                return CreateObject(obja);
            }
        }

        private SecurityDescriptor GetSecurityDescriptor()
        {
            if (!String.IsNullOrEmpty(Sddl))
            {
                return new SecurityDescriptor(Sddl);
            }
            return SecurityDescriptor;
        }

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
                objects.Add((NtObject)DoCreateObject(ResolvePath(), ObjectAttributes, Root, SecurityQualityOfService, GetSecurityDescriptor()));
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
                WriteObject(DoCreateObject(ResolvePath(), ObjectAttributes, Root, SecurityQualityOfService, GetSecurityDescriptor()));
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
        protected virtual void Dispose(bool disposing)
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

        /// <summary>
        /// Finalizer.
        /// </summary>
         ~NtObjectBaseCmdlet()
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
    /// Base object cmdlet which has an access parameter.
    /// </summary>
    /// <typeparam name="T">The access enumeration type.</typeparam>
    public abstract class NtObjectBaseCmdletWithAccess<T> : NtObjectBaseCmdlet where T : struct, IConvertible
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
            return NtObject.OpenWithType(TypeName, Path, Root, Access);
        }
    }

    /// <summary>
    /// <para type="synopsis">Create a new security descriptor which can be used on NT objects.</para>
    /// <para type="description">This cmdlet creates a new instance of a SecurityDescriptor object. This can be 
    /// used directly with one of the New-Nt* cmdlets (via the -SecurityDescriptor parameter) or by calling
    /// SetSecurityDescriptor on an existing object (assume the object has been opened with the correct permissions.
    /// </para>
    /// </summary>
    /// <example>
    ///   <code>$sd = New-NtSecurityDescriptor</code>
    ///   <para>Create a new security descriptor object.</para>
    /// </example>
    /// <example>
    ///   <code>$sd = New-NtSecurityDescriptor -Sddl "O:BAG:BAD:(A;;GA;;;WD)"</code>
    ///   <para>Create a new security descriptor object from an SDDL string</para>
    /// </example>
    /// <example>
    ///   <code>$sd = New-NtSecurityDescriptor -NullDacl</code>
    ///   <para>Create a new security descriptor object with a NULL DACL.</para>
    /// </example>
    /// <example>
    ///   <code>$sd = New-NtSecurityDescriptor -Sddl "D:(A;;GA;;;WD)"&#x0A;$obj = New-NtDirectory \BaseNamedObjects\ABC -SecurityDescriptor $sd</code>
    ///   <para>Create a new object directory with an explicit security descriptor.</para>
    /// </example>
    [Cmdlet(VerbsCommon.New, "NtSecurityDescriptor")]
    [OutputType(typeof(SecurityDescriptor))]
    public sealed class NewNtSecurityDescriptorCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify to create the security descriptor with a NULL DACL.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter NullDacl { get; set; }

        /// <summary>
        /// <para type="description">Specify to create the security descriptor from an SDDL representation.</para>
        /// </summary>
        [Parameter]
        public string Sddl { get; set; }

        /// <summary>
        /// <para type="description">Specify to create the security descriptor from the default DACL of a token object.</para>
        /// </summary>
        [Parameter]
        public NtToken Token { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            SecurityDescriptor sd = null;
            if (!String.IsNullOrWhiteSpace(Sddl))
            {
                sd = new SecurityDescriptor(Sddl);
            }
            else if (Token != null)
            {
                sd = new SecurityDescriptor(Token);
            }
            else
            {
                sd = new SecurityDescriptor
                {
                    Dacl = new Acl()
                };
                sd.Dacl.NullAcl = NullDacl;
            }

            WriteObject(sd);
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
    [Cmdlet("Use", "NtObject")]
    public class UseNtObjectCmdlet : Cmdlet, IDisposable
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
            PSObject psobj = obj as PSObject;
            if (psobj != null)
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
            if (InputObject is IEnumerable)
            {
                foreach (object obj in ((IEnumerable)InputObject))
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
    public class NtStatusResult
    {
        /// <summary>
        /// The numeric value of the status code.
        /// </summary>
        public uint Status { get; private set; }
        /// <summary>
        /// The name of the status code if known.
        /// </summary>
        public string StatusName { get; private set; }
        /// <summary>
        /// Corresponding message text.
        /// </summary>
        public string Message { get; private set; }
        /// <summary>
        /// Win32 error code.
        /// </summary>
        public int Win32Error { get; private set; }

        internal NtStatusResult(NtStatus status)
        {
            Status = (uint)status;
            Message = NtObjectUtils.GetNtStatusMessage(status);
            Win32Error = NtObjectUtils.MapNtStatusToDosError(status);
            StatusName = status.ToString();
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
    [Cmdlet(VerbsCommon.Get, "NtStatus")]
    public class GetNtStatusCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify a NTSTATUS code to retrieve.</para>
        /// </summary>
        [Parameter(Position = 0)]
        public int? Status { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (!Status.HasValue)
            {
                WriteObject(Enum.GetValues(typeof(NtStatus)).Cast<NtStatus>().Select(s => new NtStatusResult(s)), false);
            }
            else
            {
                WriteObject(new NtStatusResult(Status.Value));
            }
        }
    }

    /// <summary>
    /// Base class for child object visitor.
    /// </summary>
    /// <typeparam name="O">The type of NT object.</typeparam>
    /// <typeparam name="A">The access rights type.</typeparam>
    public abstract class BaseGetNtChildObjectCmdlet<O, A> : PSCmdlet where A : struct where O : NtObject
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
            if (script_block.InvokeWithArg<object>(null, args) is PSObject result 
                && result.BaseObject is bool b)
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
}
