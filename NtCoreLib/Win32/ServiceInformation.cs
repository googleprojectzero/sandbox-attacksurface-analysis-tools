//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

using Microsoft.Win32;
using System.Collections.Generic;
using System.IO;
using System.Security;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Class representing the information about a service.
    /// </summary>
    public class ServiceInformation
    {
        /// <summary>
        /// The name of the service.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The security descriptor of the service.
        /// </summary>
        public SecurityDescriptor SecurityDescriptor { get; }
        /// <summary>
        /// The list of triggers for the service.
        /// </summary>
        public IEnumerable<ServiceTriggerInformation> Triggers { get; }
        /// <summary>
        /// The service SID setting.
        /// </summary>
        public ServiceSidType SidType { get; }
        /// <summary>
        /// The service launch protected setting.
        /// </summary>
        public ServiceLaunchProtectedType LaunchProtected { get; }
        /// <summary>
        /// The service required privileges.
        /// </summary>
        public IEnumerable<string> RequiredPrivileges { get; }
        /// <summary>
        /// The service type.
        /// </summary>
        public ServiceType ServiceType { get; }
        /// <summary>
        /// Service start type.
        /// </summary>
        public ServiceStartType StartType { get; }
        /// <summary>
        /// Error control.
        /// </summary>
        public ServiceErrorControl ErrorControl { get; }
        /// <summary>
        /// Binary path name.
        /// </summary>
        public string BinaryPathName { get; }
        /// <summary>
        /// Load order group.
        /// </summary>
        public string LoadOrderGroup { get; }
        /// <summary>
        /// Tag ID for load order.
        /// </summary>
        public int TagId { get; }
        /// <summary>
        /// Dependencies.
        /// </summary>
        public IEnumerable<string> Dependencies { get; }
        /// <summary>
        /// Display name.
        /// </summary>
        public string DisplayName { get; }
        /// <summary>
        /// Service start name. For user mode services this is the username, for drivers it's the driver name.
        /// </summary>
        public string ServiceStartName { get; }
        /// <summary>
        /// Indicates this service is set to delayed automatic start.
        /// </summary>
        public bool DelayedAutoStart { get; }
        /// <summary>
        /// The user name this service runs under.
        /// </summary>
        public string UserName { get; }
        /// <summary>
        /// Type of service host when using Win32Share.
        /// </summary>
        public string ServiceHostType { get; }
        /// <summary>
        /// Service main function when using Win32Share.
        /// </summary>
        public string ServiceMain { get; }
        /// <summary>
        /// Image path for the service.
        /// </summary>
        public string ImagePath { get; }
        /// <summary>
        /// Get name of the target image, either the ServiceDll or ImagePath.
        /// </summary>
        public string ImageName => string.IsNullOrEmpty(ServiceDll) ? Path.GetFileName(ImagePath) : Path.GetFileName(ServiceDll);
        /// <summary>
        /// Service DLL if a shared process server.
        /// </summary>
        public string ServiceDll { get; }
        /// <summary>
        /// The name of the machine this service was found on.
        /// </summary>
        public string MachineName { get; }
        /// <summary>
        /// Indicates if this service process is grouped with others.
        /// </summary>
        public bool SvcHostSplitDisabled { get; }

        private static RegistryKey OpenKeySafe(RegistryKey rootKey, string path)
        {
            try
            {
                return rootKey.OpenSubKey(path);
            }
            catch (SecurityException)
            {
                return null;
            }
        }

        private static string ReadStringFromKey(RegistryKey rootKey, string keyName, string valueName)
        {
            RegistryKey key = rootKey;

            try
            {
                if (keyName != null)
                {
                    key = OpenKeySafe(rootKey, keyName);
                }

                string valueString = string.Empty;
                if (key != null)
                {
                    object valueObject = key.GetValue(valueName);
                    if (valueObject != null)
                    {
                        valueString = valueObject.ToString();
                    }
                }

                return valueString.TrimEnd('\0');
            }
            finally
            {
                if (key != null && key != rootKey)
                {
                    key.Close();
                }
            }
        }

        internal ServiceInformation(string machine_name, string name, SecurityDescriptor sd, 
            IEnumerable<ServiceTriggerInformation> triggers, ServiceSidType sid_type,
            ServiceLaunchProtectedType launch_protected, IEnumerable<string> required_privileges,
            SafeStructureInOutBuffer<QUERY_SERVICE_CONFIG> config, bool delayed_auto_start)
        {
            Name = name;
            SecurityDescriptor = sd;
            Triggers = triggers;
            SidType = sid_type;
            LaunchProtected = launch_protected;
            RequiredPrivileges = required_privileges;

            if (config == null)
            {
                BinaryPathName = string.Empty;
                LoadOrderGroup = string.Empty;
                Dependencies = new string[0];
                DisplayName = string.Empty;
                ServiceStartName = string.Empty;
                return;
            }

            var result = config.Result;
            ServiceType = result.dwServiceType;
            StartType = result.dwStartType;
            ErrorControl = result.dwErrorControl;
            BinaryPathName = result.lpBinaryPathName.GetString();
            LoadOrderGroup = result.lpLoadOrderGroup.GetString();
            TagId = result.dwTagId;
            Dependencies = result.lpLoadOrderGroup.GetMultiString();
            DisplayName = result.lpDisplayName.GetString();
            ServiceStartName = result.lpServiceStartName.GetString();
            DelayedAutoStart = delayed_auto_start;
            MachineName = machine_name ?? string.Empty;
            ImagePath = string.Empty;
            ServiceDll = string.Empty;
            ServiceHostType = string.Empty;
            ServiceMain = string.Empty;

            // TODO: Maybe try and query using remote registry service?
            if (!string.IsNullOrEmpty(MachineName))
                return;
            ImagePath = Win32Utils.GetImagePathFromCommandLine(BinaryPathName);
            using (RegistryKey key = OpenKeySafe(Registry.LocalMachine, $@"SYSTEM\CurrentControlSet\Services\{Name}"))
            {
                if (key != null)
                {
                    UserName = ReadStringFromKey(key, null, "ObjectName");
                    ServiceDll = ReadStringFromKey(key, "Parameters", "ServiceDll");
                    if (string.IsNullOrEmpty(ServiceDll))
                    {
                        ServiceDll = ReadStringFromKey(key, null, "ServiceDll");
                    }

                    if (!string.IsNullOrEmpty(ServiceDll))
                    {
                        string[] args = Win32Utils.ParseCommandLine(BinaryPathName);
                        for (int i = 0; i < args.Length - 1; ++i)
                        {
                            if (args[i] == "-k")
                            {
                                ServiceHostType = args[i + 1];
                                break;
                            }
                        }

                        ServiceMain = ReadStringFromKey(key, "Parameters", "ServiceMain");
                        if (string.IsNullOrEmpty(ServiceMain))
                        {
                            ServiceMain = "ServiceMain";
                        }
                    }

                    if (key.GetValue("SvcHostSplitDisable") is int disable)
                    {
                        SvcHostSplitDisabled = disable != 0;
                    }
                }
            }
        }

        internal ServiceInformation(string machine_name, string name) 
            : this(machine_name, name, null,
                new ServiceTriggerInformation[0], ServiceSidType.None,
                ServiceLaunchProtectedType.None, new string[0], null, false)
        {
        }
    }
#pragma warning restore
}
