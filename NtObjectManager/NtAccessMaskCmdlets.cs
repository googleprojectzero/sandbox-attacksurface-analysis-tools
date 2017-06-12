//  Copyright 2017 Google Inc. All Rights Reserved.
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
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Convert a specific object access to an AccessMask or GenericAccess.</para>
    /// <para type="description">This cmdlet allows you to convert a specific object access to an
    /// AccessMask or GenericAccess for use in general functions.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-GetNtAccessMask -Process DupHandle</code>
    ///   <para>Get the Process DupHandle access right as an AccessMask</para>
    /// </example>
    /// <example>
    ///   <code>Get-GetNtAccessMask -Process DupHandle -ToGenericAccess</code>
    ///   <para>Get the Process DupHandle access right as a GenericAccess value</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtAccessMask")]
    public sealed class GetNtAccessMaskCmdlet : Cmdlet
    {
        private AccessMask MapGeneric(string typename, AccessMask access_mask)
        {
            if (!MapGenericRights)
            {
                return access_mask;
            }
            NtType type = NtType.GetTypeByName(typename, false);
            System.Diagnostics.Debug.Assert(type != null);
            return type.MapGenericRights(access_mask);
        }

        /// <summary>
        /// <para type="description">Specify a raw access mask.</para>
        /// </summary>
        [Parameter]
        public AccessMask AccessMask { get; set; }
        /// <summary>
        /// <para type="description">Return access as GenericAccess.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter ToGenericAccess { get; set; }
        /// <summary>
        /// <para type="description">Return access as specific access type based on the NtType.</para>
        /// </summary>
        [Parameter]
        public string ToSpecificAccess { get; set; }
        /// <summary>
        /// <para type="description">Specify that any generic rights should be mapped to type specific rights.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter MapGenericRights { get; set; }
        /// <summary>
        /// <para type="description">Specify File access rights.</para>
        /// </summary>
        [Parameter]
        public FileAccessRights File { get; set; }
        /// <summary>
        /// <para type="description">Specify File Directory access rights.</para>
        /// </summary>
        [Parameter]
        public FileDirectoryAccessRights FileDirectory { get; set; }
        /// <summary>
        /// <para type="description">Specify IO Completion access rights.</para>
        /// </summary>
        [Parameter]
        public IoCompletionAccessRights IoCompletion { get; set; }
        /// <summary>
        /// <para type="description">Specify Mutant access rights.</para>
        /// </summary>
        [Parameter]
        public MutantAccessRights Mutant { get; set; }
        /// <summary>
        /// <para type="description">Specify Semaphore access rights.</para>
        /// </summary>
        [Parameter]
        public SemaphoreAccessRights Semaphore { get; set; }
        /// <summary>
        /// <para type="description">Specify Registry Transaction access rights.</para>
        /// </summary>
        [Parameter]
        public RegistryTransactionAccessRights RegistryTransaction { get; set; }
        /// <summary>
        /// <para type="description">Specify ALPC Port access rights.</para>
        /// </summary>
        [Parameter]
        public AlpcAccessRights AlpcPort { get; set; }
        /// <summary>
        /// <para type="description">Specify Section access rights.</para>
        /// </summary>
        [Parameter]
        public SectionAccessRights Section { get; set; }
        /// <summary>
        /// <para type="description">Specify Key access rights.</para>
        /// </summary>
        [Parameter]
        public KeyAccessRights Key { get; set; }
        /// <summary>
        /// <para type="description">Specify Event access rights.</para>
        /// </summary>
        [Parameter]
        public EventAccessRights Event { get; set; }
        /// <summary>
        /// <para type="description">Specify Symbolic Link access rights.</para>
        /// </summary>
        [Parameter]
        public SymbolicLinkAccessRights SymbolicLink { get; set; }
        /// <summary>
        /// <para type="description">Specify Token access rights.</para>
        /// </summary>
        [Parameter]
        public TokenAccessRights Token { get; set; }
        /// <summary>
        /// <para type="description">Specify Generic access rights.</para>
        /// </summary>
        [Parameter]
        public GenericAccessRights Generic { get; set; }
        /// <summary>
        /// <para type="description">Specify Directory access rights.</para>
        /// </summary>
        [Parameter]
        public DirectoryAccessRights Directory { get; set; }
        /// <summary>
        /// <para type="description">Specify Thread access rights.</para>
        /// </summary>
        [Parameter]
        public ThreadAccessRights Thread { get; set; }
        /// <summary>
        /// <para type="description">Specify Debug Object access rights.</para>
        /// </summary>
        [Parameter]
        public DebugAccessRights DebugObject { get; set; }
        /// <summary>
        /// <para type="description">Specify Job access rights.</para>
        /// </summary>
        [Parameter]
        public JobAccessRights Job { get; set; }
        /// <summary>
        /// <para type="description">Specify Process access rights.</para>
        /// </summary>
        [Parameter]
        public ProcessAccessRights Process { get; set; }

        /// <summary>
        /// Overridden ProcessRecord
        /// </summary>
        protected override void ProcessRecord()
        {
            AccessMask mask = AccessMask;

            mask |= MapGeneric("File", File);
            mask |= MapGeneric("File", FileDirectory);
            mask |= MapGeneric("IoCompletion", IoCompletion);
            mask |= MapGeneric("Mutant", Mutant);
            mask |= MapGeneric("Semaphore", Semaphore);
            mask |= MapGeneric("RegistryTransaction", RegistryTransaction);
            mask |= MapGeneric("ALPC Port", AlpcPort);
            mask |= MapGeneric("Section", Section);
            mask |= MapGeneric("Key", Key);
            mask |= MapGeneric("Event", Event);
            mask |= MapGeneric("SymbolicLink", SymbolicLink);
            mask |= MapGeneric("Token", Token);
            mask |= Generic;
            mask |= MapGeneric("Directory", Directory);
            mask |= MapGeneric("Thread", Thread);
            mask |= MapGeneric("DebugObject", DebugObject);
            mask |= MapGeneric("Job", Job);
            mask |= MapGeneric("Process", Process);

            if (ToGenericAccess)
            {
                WriteObject(mask.ToGenericAccess());
            }
            else if (String.IsNullOrEmpty(ToSpecificAccess))
            {
                WriteObject(mask);
            }
            else
            {
                NtType type = NtType.GetTypeByName(ToSpecificAccess, false);
                if (type == null)
                {
                    throw new ArgumentException(String.Format("'{0}' is not a valid NT type name", ToSpecificAccess));
                }
                WriteObject(mask.ToSpecificAccess(type.AccessRightsType));
            }
        }
    }
}
