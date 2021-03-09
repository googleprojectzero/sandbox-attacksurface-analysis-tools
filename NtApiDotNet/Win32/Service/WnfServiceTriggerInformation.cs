﻿//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Linq;

namespace NtApiDotNet.Win32.Service
{
    /// <summary>
    /// Service trigger for a WNF event.
    /// </summary>
    public class WnfServiceTriggerInformation : ServiceTriggerInformation
    {
        /// <summary>
        /// The WNF name.
        /// </summary>
        public NtWnf Name { get; }

        private protected override string GetSubTypeDescription()
        {
            if (SubType == CUSTOM_SYSTEM_STATE_CHANGE_EVENT_GUID && Name != null)
            {
                return $"{base.GetSubTypeDescription()} {Name.Name}";
            }
            return base.GetSubTypeDescription();
        }

        internal WnfServiceTriggerInformation(SERVICE_TRIGGER trigger)
            : base(trigger)
        {
            var data = CustomData.FirstOrDefault();
            if (data?.RawData?.Length != 8)
            {
                return;
            }

            Name = NtWnf.Open(BitConverter.ToUInt64(data.RawData, 0), true, false).GetResultOrDefault();
        }
    }
#pragma warning restore
}
