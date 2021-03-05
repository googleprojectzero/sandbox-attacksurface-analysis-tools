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

namespace NtApiDotNet.Win32.Service
{
    /// <summary>
    /// A service trigger for an ETW event.
    /// </summary>
    public sealed class EtwServiceTriggerInformation : ServiceTriggerInformation
    {
        /// <summary>
        /// The security descriptor for the ETW event. Needs administrator privileges.
        /// </summary>
        public SecurityDescriptor SecurityDescriptor { get; }

        /// <summary>
        /// Trigger the service.
        /// </summary>
        public override void Trigger()
        {
            using (var reg = EventTracing.Register(SubType))
            {
                reg.Write();
            }
        }

        private protected override string GetSubTypeDescription()
        {
            return $"{base.GetSubTypeDescription()} {EventTracing.GetProviderName(SubType) ?? SubType.ToString("B")}";
        }

        internal EtwServiceTriggerInformation(SERVICE_TRIGGER trigger)
            : base(trigger)
        {
            var sd = EventTracing.QueryTraceSecurity(SubType, false);
            if (sd.IsSuccess)
            {
                SecurityDescriptor = sd.Result;
            }
        }
    }
#pragma warning restore
}
