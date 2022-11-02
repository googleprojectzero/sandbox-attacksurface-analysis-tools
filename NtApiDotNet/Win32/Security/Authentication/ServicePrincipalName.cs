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

using System;
using System.Collections.Generic;
using System.Net;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to represent a service principal name.
    /// </summary>
    public class ServicePrincipalName
    {
        /// <summary>
        /// SPN service class.
        /// </summary>
        public string ServiceClass { get; set; }
        /// <summary>
        /// SPN service name.
        /// </summary>
        public string ServiceName { get; set; }
        /// <summary>
        /// SPN instance name.
        /// </summary>
        public string InstanceName { get; set; }
        /// <summary>
        /// SPN instance port.
        /// </summary>
        public int InstancePort { get; set; }
        /// <summary>
        /// SPN referrer.
        /// </summary>
        public string Referrer { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="service_class">The service class name.</param>
        /// <param name="instance_name">The name of the instance.</param>
        /// <param name="instance_port">The optional instance port. Set to 0 to exclude.</param>
        /// <param name="service_name">The optional service name.</param>
        public ServicePrincipalName(string service_class, string instance_name, int instance_port = 0, string service_name = null)
        {
            ServiceClass = service_class;
            InstanceName = instance_name;
            InstancePort = instance_port;
            ServiceName = service_name ?? instance_name;
        }

        /// <summary>
        /// Parse an SPN string to a class.
        /// </summary>
        /// <param name="spn">The SPN string.</param>
        /// <returns>The parsed class.</returns>
        /// <exception cref="FormatException">Thrown in invalid SPN.</exception>
        public static ServicePrincipalName Parse(string spn)
        {
            if (string.IsNullOrWhiteSpace(spn))
            {
                throw new FormatException($"SPN cannot be null or whitespace.");
            }

            string[] parts = spn.Split('/');
            if (parts.Length < 2)
                throw new FormatException("SPN must contain at least two components.");
            if (parts.Length > 3)
                throw new FormatException("SPN must contain at most three components.");

            string service_class = parts[0];
            string instance_name = parts[1];

            if (string.IsNullOrEmpty(service_class))
                throw new FormatException("Service class can't be empty.");

            ushort instance_port = 0;
            string[] instance_parts = instance_name.Split(':');
            if (instance_parts.Length > 1)
            {
                if (instance_parts[1].Length > 0 && !ushort.TryParse(instance_parts[1], out instance_port))
                    throw new FormatException("Invalid instance port number.");
                instance_name = instance_parts[0];
            }
            if (string.IsNullOrEmpty(instance_name))
                throw new FormatException("Instance name can't be empty.");

            string service_name = parts.Length > 2 ? parts[2] : instance_name;
            if (string.IsNullOrEmpty(service_name))
                throw new FormatException("Service name can't be empty.");

            return new ServicePrincipalName(service_class, instance_name, instance_port, service_name);
        }

        /// <summary>
        /// Try and parse an SPN string to a class.
        /// </summary>
        /// <param name="spn">The SPN string.</param>
        /// <param name="result">The result class.</param>
        /// <returns>True if the SPN was parsed successfully.</returns>
        /// <exception cref="FormatException">Thrown in invalid SPN.</exception>
        public static bool TryParse(string spn, out ServicePrincipalName result)
        {
            result = null;
            try
            {
                result = Parse(spn);
                return true;
            }
            catch(FormatException)
            {
                return false;
            }
        }

        /// <summary>
        /// Convert SPN to a string.
        /// </summary>
        /// <returns>The SPN string.</returns>
        public override string ToString()
        {
            if (string.IsNullOrEmpty(ServiceClass) || ServiceName.Contains("/"))
            {
                throw new ArgumentException("Service class can't be null or empty or contain a forward slash.", nameof(ServiceClass));
            }

            if (string.IsNullOrEmpty(ServiceName) || ServiceName.Contains("/"))
            {
                throw new ArgumentException("Service name can't be null or empty or contain a forward slash.", nameof(ServiceClass));
            }

            List<string> parts = new List<string>();
            parts.Add(ServiceClass);

            string instance_name = InstanceName ?? ServiceName;
            if (string.IsNullOrEmpty(instance_name) || instance_name.Contains("/"))
            {
                throw new ArgumentException("Instance name can't be empty or contain a forward slash.", nameof(InstanceName));
            }

            if (InstancePort < 0 || InstancePort > ushort.MaxValue)
            {
                throw new ArgumentException($"Instance port must be between 0 and {ushort.MaxValue} inclusive.", nameof(InstancePort));
            }

            if (InstancePort != 0)
            {
                parts.Add($"{instance_name}:{InstancePort}");
            }
            else
            {
                parts.Add(instance_name);
            }

            string service_name = ServiceName;
            if (Referrer != null && IPAddress.TryParse(service_name, out IPAddress _))
            {
                if (Referrer.Length == 0)
                    throw new ArgumentException("Referrer can't be empty.", nameof(Referrer));
                service_name = Referrer;
            }

            if (!instance_name.Equals(service_name, StringComparison.OrdinalIgnoreCase))
            {
                parts.Add(service_name);
            }

            return string.Join("/", parts);
        }
    }
}
