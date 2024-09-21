//  Copyright 2021 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Service
{
    /// <summary>
    /// Service trigger for firewall port interface.
    /// </summary>
    public sealed class FirewallServiceTriggerInformation : ServiceTriggerInformation
    {
        /// <summary>
        /// The port for the firewall service trigger.
        /// </summary>
        public string Port { get; }
        /// <summary>
        /// The protocol for the firewall service trigger.
        /// </summary>
        public string Protocol { get; }
        /// <summary>
        /// The protocol for the firewall service trigger.
        /// </summary>
        public string ExecutablePath { get; }
        /// <summary>
        /// The protocol for the firewall service trigger.
        /// </summary>
        public string User { get; }

        internal FirewallServiceTriggerInformation(SERVICE_TRIGGER trigger) : base(trigger)
        {
            if (CustomData.Count > 0)
            {
                var data = CustomData[0].DataArray;
                Port = data.Length > 0 ? data[0] : string.Empty;
                Protocol = data.Length > 1 ? data[1] : string.Empty;
                ExecutablePath = data.Length > 2 ? data[2] : string.Empty;
                User = data.Length > 3 ? data[3] : string.Empty;
            }
        }
    }
}
