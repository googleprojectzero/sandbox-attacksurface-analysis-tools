//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Open a NT debug object by path.</para>
    /// <para type="description">This cmdlet opens an existing NT debug object. The absolute path to the object in the NT object manager name space must be specified. 
    /// It's also possible to create the object relative to an existing object by specified the -Root parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtDebug \BaseNamedObjects\ABC</code>
    ///   <para>Get a debug object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = Get-NtDebug ABC -Root $root</code>
    ///   <para>Get a debug object with a relative path.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtDebug -Path \BaseNamedObjects\ABC&#x0A;$obj.Wait()</code>
    ///   <para>Get a debug object, wait for it to be set.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtDebug -Path \BaseNamedObjects\ABC&#x0A;$obj.Set()</code>
    ///   <para>Get a debug object, and set it.</para>
    /// </example>
    /// <example>
    ///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = Get-NtDebug ABC</code>
    ///   <para>Get a debug object with a relative path based on the current location.
    ///   </para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtDebug")]
    [OutputType(typeof(NtDebug))]
    public sealed class GetNtDebugCmdlet : NtObjectBaseCmdletWithAccess<DebugAccessRights>
    {
        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected override bool CanCreateDirectories()
        {
            return false;
        }

        /// <summary>
        /// <para type="description">The NT object manager path to the object to use.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public override string Path { get; set; }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtDebug.Open(obj_attributes, Access);
        }
    }

    /// <summary>
    /// <para type="synopsis">Create a new NT debug object.</para>
    /// <para type="description">This cmdlet creates a new NT debug object. The absolute path to the object in the NT object manager name space can be specified. 
    /// It's also possible to create the object relative to an existing object by specified the -Root parameter. If no path is specified than an unnamed object will be created which
    /// can only be duplicated by handle. You can also attach a process to the new debug object immediately after creation.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = New-NtDebug</code>
    ///   <para>Create a new anonymous debug object.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtDebug \BaseNamedObjects\ABC</code>
    ///   <para>Create a new debug object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = New-NtDebug ABC -Root $root</code>
    ///   <para>Create a new debug object with a relative path.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = New-NtDebug ABC</code>
    ///   <para>Create a new debug object with a relative path based on the current location.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtDebug -ProcessId 12345</code>
    ///   <para>Create a new anonymous debug object and attach to PID 12345.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtDebug -Process $proc</code>
    ///   <para>Create a new anonymous debug object and attach to a process object.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtDebug", DefaultParameterSetName = "NoAttach")]
    [OutputType(typeof(NtDebug))]
    public sealed class NewNtDebugCmdlet : NtObjectBaseCmdletWithAccess<DebugAccessRights>
    {
        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected override bool CanCreateDirectories()
        {
            return true;
        }

        /// <summary>
        /// <para type="description">Specify a process ID to attach to after creation.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "AttachPid")]
        [Alias("pid")]
        public int ProcessId { get; set; }

        /// <summary>
        /// <para type="description">Specify a process to attach to after creation.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "AttachProcess")]
        public NtProcess Process { get; set; }

        /// <summary>
        /// <para type="description">Specify flags for create.</para>
        /// </summary>
        [Parameter]
        public DebugObjectFlags Flags { get; set; }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            using (var obj = NtDebug.Create(obj_attributes, Access, Flags))
            {
                switch (ParameterSetName)
                {
                    case "AttachPid":
                        obj.Attach(ProcessId);
                        break;
                    case "AttachProcess":
                        obj.Attach(Process);
                        break;
                }
                return obj.Duplicate();
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Wait for an event on a debug object.</para>
    /// <para type="description">This cmdlet allows you to issue a wait for an on a debug object. The timeout
    /// value is a combination of all the allowed time parameters, e.g. if you specify 1 second and 1000 milliseconds it will
    /// actually wait 2 seconds in total. Specifying -Infinite overrides the time parameters and will wait indefinitely.</para>
    /// </summary>
    /// <example>
    ///   <code>$ev = Start-NtDebugWait $dbg -Seconds 10</code>
    ///   <para>Wait for 10 seconds for a debug event to be returned.</para>
    /// </example>
    /// <example>
    ///   <code>$ev = Start-NtDebugWait $dbg -Infinite</code>
    ///   <para>Wait indefinitely for a debug event to be returned.</para>
    /// </example>
    /// <example>
    ///   <code>$ev = Start-NtDebugWait $dbg -Infinite -Alterable</code>
    ///   <para>Wait indefinitely for a debug event to be returned in an alertable state.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet("Start", "NtDebugWait")]
    [OutputType(typeof(DebugEvent))]
    public sealed class StartNtDebugWait : GetNtWaitTimeout
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public StartNtDebugWait()
        {
            ContinueStatus = NtStatus.DBG_CONTINUE;
        }

        /// <summary>
        /// <para type="description">Specify the debug object to wait on.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public NtDebug DebugObject { get; set; }

        /// <summary>
        /// <para type="description">Specify the wait should be alertable.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Alertable { get; set; }

        /// <summary>
        /// <para type="description">Specify an event to continue before waiting.</para>
        /// </summary>
        [Parameter]
        public DebugEvent ContinueEvent { get; set; }

        /// <summary>
        /// <para type="description">If continue event specified then this is the status to use.</para>
        /// </summary>
        [Parameter]
        public NtStatus ContinueStatus { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (ContinueEvent != null)
            {
                DebugObject.Continue(ContinueEvent.ProcessId, ContinueEvent.ThreadId, ContinueStatus);
            }
            WriteObject(DebugObject.WaitForDebugEvent(Alertable, GetTimeout()));
        }
    }

    /// <summary>
    /// <para type="synopsis">Attach a process to a debug object.</para>
    /// <para type="description">This cmdlet attaches a process to a debug object. You can remove it again using
    /// Remove-NtDebugProcess.</para>
    /// </summary>
    /// <example>
    ///   <code>Add-NtDebugProcess $dbg -ProcessId 12345</code>
    ///   <para>Attach process 12345 to the debug object..</para>
    /// </example>
    /// <example>
    ///   <code>Add-NtDebugProcess $dbg -Process $proc</code>
    ///   <para>Attach a process object to the debug object..</para>
    /// </example>
    [Cmdlet(VerbsCommon.Add, "NtDebugProcess")]
    public sealed class AddNtDebugProcess : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the debug object to attach the process to.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public NtDebug DebugObject { get; set; }

        /// <summary>
        /// <para type="description">Specify a process ID to attach to .</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "AttachPid")]
        [Alias("pid")]
        public int ProcessId { get; set; }

        /// <summary>
        /// <para type="description">Specify a process to attach to.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "AttachProcess")]
        public NtProcess Process { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            switch (ParameterSetName)
            {
                case "AttachPid":
                    DebugObject.Attach(ProcessId);
                    break;
                case "AttachProcess":
                    DebugObject.Attach(Process);
                    break;
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Detach a process from a debug object.</para>
    /// <para type="description">This cmdlet detachs a process remove a debug object.</para>
    /// </summary>
    /// <example>
    ///   <code>Remove-NtDebugProcess $dbg -ProcessId 12345</code>
    ///   <para>Detach process 12345 from the debug object..</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtDebugProcess $dbg -Process $proc</code>
    ///   <para>Detach process object from the debug object..</para>
    /// </example>
    [Cmdlet(VerbsCommon.Remove, "NtDebugProcess")]
    public sealed class RemoveNtDebugProcess : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the debug object to debug the process from.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public NtDebug DebugObject { get; set; }

        /// <summary>
        /// <para type="description">Specify a process ID to detach.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "DetachPid")]
        [Alias("pid")]
        public int ProcessId { get; set; }

        /// <summary>
        /// <para type="description">Specify a process to detach.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "DetachProcess")]
        public NtProcess Process { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            switch (ParameterSetName)
            {
                case "DetachPid":
                    DebugObject.Detach(ProcessId);
                    break;
                case "DetachProcess":
                    DebugObject.Detach(Process);
                    break;
            }
        }
    }
}
