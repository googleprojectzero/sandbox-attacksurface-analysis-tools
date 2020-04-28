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

using NtApiDotNet.Win32.Security.Native;
using System;
using System.Text;

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

        private ServicePrincipalName()
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="service_class">The service class name.</param>
        /// <param name="instance_name">The name of the instance.</param>
        public ServicePrincipalName(string service_class, string instance_name)
        {
            ServiceClass = service_class;
            InstanceName = instance_name;
        }

        /// <summary>
        /// Parse an SPN string to a class.
        /// </summary>
        /// <param name="spn">The SPN string.</param>
        /// <returns>The parsed class.</returns>
        /// <exception cref="FormatException">Thrown in invalid SPN.</exception>
        public static ServicePrincipalName Parse(string spn)
        {
            if (!TryParse(spn, out ServicePrincipalName result))
            {
                throw new FormatException("SPN string was invalid");
            }
            return result;
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

            OptionalInt32 cServiceClass = 1;
            StringBuilder ServiceClass = new StringBuilder(1);
            OptionalInt32 cServiceName = 1;
            StringBuilder ServiceName = new StringBuilder(1);
            OptionalInt32 cInstanceName = 1;
            StringBuilder InstanceName = new StringBuilder(1);
            OptionalUInt16 InstancePort = 0;

            var err = SecurityNativeMethods.DsCrackSpn(spn, cServiceClass, ServiceClass,
                cServiceName, ServiceName, cInstanceName, InstanceName, InstancePort);
            if (err != Win32Error.ERROR_BUFFER_OVERFLOW)
            {
                return false;
            }

            ServiceClass = new StringBuilder(cServiceClass.Value);
            ServiceName = new StringBuilder(cServiceName.Value);
            InstanceName = new StringBuilder(cInstanceName.Value);

            if (SecurityNativeMethods.DsCrackSpn(spn, cServiceClass, ServiceClass,
                cServiceName, ServiceName, cInstanceName, InstanceName, InstancePort) != Win32Error.SUCCESS)
            {
                return false;
            }

            result = new ServicePrincipalName()
            {
                ServiceClass = ServiceClass.ToString(),
                ServiceName = ServiceName.ToString(),
                InstanceName = InstanceName.ToString(),
                InstancePort = InstancePort.Value
            };

            return true;
        }

        /// <summary>
        /// Convert SPN to a string.
        /// </summary>
        /// <returns>The SPN string.</returns>
        public override string ToString()
        {
            int length = 0;
            Win32Error err = SecurityNativeMethods.DsMakeSpn(ServiceClass, ServiceName, InstanceName,
                (ushort)InstancePort, Referrer, ref length, null);
            if (err == Win32Error.SUCCESS)
                return string.Empty;
            if (err != Win32Error.ERROR_BUFFER_OVERFLOW)
                throw new NtException(err.MapDosErrorToStatus());
            StringBuilder builder = new StringBuilder(length);
            SecurityNativeMethods.DsMakeSpn(ServiceClass, ServiceName, InstanceName,
                (ushort)InstancePort, Referrer, ref length, builder).ToNtException();
            return builder.ToString();
        }
    }
}
