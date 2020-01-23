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


namespace NtApiDotNet.Win32
{
#pragma warning disable 1591
    public class EtwServiceTriggerInformation : ServiceTriggerInformation
    {
        public SecurityDescriptor SecurityDescriptor { get; }

        public override void Trigger()
        {
            using (var reg = EventTracing.Register(SubType))
            {
                reg.Write();
            }
        }

        internal EtwServiceTriggerInformation(SERVICE_TRIGGER trigger) 
            : base(trigger)
        {
            var sd = EventTracing.QueryTraceSecurity(SubType, false);
            if (sd.IsSuccess)
            {
                SecurityDescriptor = sd.Result;
            }
            else
            {
                SecurityDescriptor = new SecurityDescriptor();
            }
        }
    }
#pragma warning restore
}
