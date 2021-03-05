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

using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Service
{
    /// <summary>
    /// Service trigger for an RPC interface.
    /// </summary>
    public class RpcInterfaceServiceTriggerInformation : ServiceTriggerInformation
    {
        /// <summary>
        /// List of interface ID for the RPC server.
        /// </summary>
        public IReadOnlyList<Guid> InterfaceId { get; }

        private protected override string GetSubTypeDescription()
        {
            return $"{base.GetSubTypeDescription()} {string.Join(", ", InterfaceId)}";
        }

        internal RpcInterfaceServiceTriggerInformation(SERVICE_TRIGGER trigger) : base(trigger)
        {
            if (CustomData.Count > 0 && CustomData[0].DataType == ServiceTriggerDataType.String)
            {
                InterfaceId = CustomData[0].Data.Split(':').Where(s => Guid.TryParse(s,
                    out Guid _)).Select(s => Guid.Parse(s)).ToList().AsReadOnly();
            }
        }
    }
}
