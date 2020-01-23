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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32
{
#pragma warning disable 1591
    public class ServiceTriggerInformation
    {
        public ServiceTriggerType TriggerType { get; }
        public ServiceTriggerAction Action { get; }
        public Guid SubType { get; }
        public string SubTypeDescription { get; }
        public IEnumerable<ServiceTriggerCustomData> CustomData { get; }

        static Guid NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID = new Guid("4f27f2de-14e2-430b-a549-7cd48cbc8245");
        static Guid NETWORK_MANAGER_LAST_IP_ADDRESS_REMOVAL_GUID = new Guid("cc4ba62a-162e-4648-847a-b6bdf993e335");
        static Guid DOMAIN_JOIN_GUID = new Guid("1ce20aba-9851-4421-9430-1ddeb766e809");
        static Guid DOMAIN_LEAVE_GUID = new Guid("ddaf516e-58c2-4866-9574-c3b615d42ea1");
        static Guid FIREWALL_PORT_OPEN_GUID = new Guid("b7569e07-8421-4ee0-ad10-86915afdad09");
        static Guid FIREWALL_PORT_CLOSE_GUID = new Guid("a144ed38-8e12-4de4-9d96-e64740b1a524");
        static Guid MACHINE_POLICY_PRESENT_GUID = new Guid("659FCAE6-5BDB-4DA9-B1FF-CA2A178D46E0");
        static Guid USER_POLICY_PRESENT_GUID = new Guid("54FB46C8-F089-464C-B1FD-59D1B62C3B50");
        static Guid RPC_INTERFACE_EVENT_GUID = new Guid("bc90d167-9470-4139-a9ba-be0bbbf5b74d");
        static Guid NAMED_PIPE_EVENT_GUID = new Guid("1f81d131-3fac-4537-9e0c-7e7b0c2f4b55");
        static Guid CUSTOM_SYSTEM_STATE_CHANGE_EVENT_GUID = new Guid("2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9");

        private string GetSubTypeDescription()
        {
            switch (TriggerType)
            {
                case ServiceTriggerType.Custom:
                    return $"[ETW UUID] {SubType:B}";
                case ServiceTriggerType.DeviceInterfaceArrival:
                    return $"[Interface Class GUID] {SubType:B}";
                case ServiceTriggerType.GroupPolicy:
                    {
                        if (SubType == MACHINE_POLICY_PRESENT_GUID)
                        {
                            return "[Machine Policy Present]";
                        }
                        else if (SubType == USER_POLICY_PRESENT_GUID)
                        {
                            return "[User Policy Present]";
                        }
                        return $"[Unknown Group Policy] {SubType:B}";
                    }
                case ServiceTriggerType.NetworkEndpoint:
                    {
                        if (SubType == RPC_INTERFACE_EVENT_GUID)
                        {
                            return "[RPC Interface]";
                        }
                        else if (SubType == NAMED_PIPE_EVENT_GUID)
                        {
                            return "[Named Pipe]";
                        }
                        return $"[Unknown Network Endpoint] {SubType:B}";
                    }
                case ServiceTriggerType.DomainJoin:
                    {
                        if (SubType == DOMAIN_JOIN_GUID)
                        {
                            return "[Domain Join]";
                        }
                        else if (SubType == DOMAIN_LEAVE_GUID)
                        {
                            return "[Domain Leave]";
                        }
                        return $"[Unknown Domain Join] {SubType:B}";
                    }
                case ServiceTriggerType.IPAddressAvailability:
                    {
                        if (SubType == NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID)
                        {
                            return "[First IP Address Available]";
                        }
                        else if (SubType == NETWORK_MANAGER_LAST_IP_ADDRESS_REMOVAL_GUID)
                        {
                            return "[Last IP Address Available]";
                        }
                        return $"[Unknown IP Address Availability] {SubType:B}";
                    }
                case ServiceTriggerType.CustomSystemStateChange:
                    return "[CustomSystemStateChange]";
                default:
                    return $"Unknown Trigger Type: {TriggerType} SubType: {SubType}";
            }
        }

        static void ReadArray<T>(IntPtr ptr, int count, out T[] ret) where T : struct
        {
            ret = new T[count];
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(ptr, count * Marshal.SizeOf(typeof(T)), false))
            {
                buffer.ReadArray(0, ret, 0, count);
            }
        }

        internal ServiceTriggerInformation(SERVICE_TRIGGER trigger)
        {
            TriggerType = trigger.dwTriggerType;
            Action = trigger.dwAction;
            SubType = trigger.GetSubType();
            SubTypeDescription = GetSubTypeDescription();

            List<ServiceTriggerCustomData> data = new List<ServiceTriggerCustomData>();
            if (trigger.pDataItems != IntPtr.Zero && trigger.cDataItems > 0)
            {
                ReadArray(trigger.pDataItems, trigger.cDataItems, 
                    out SERVICE_TRIGGER_SPECIFIC_DATA_ITEM[] data_items);
                for (int i = 0; i < data_items.Length; ++i)
                {
                    data.Add(new ServiceTriggerCustomData(data_items[i]));
                }
            }
            CustomData = data.AsReadOnly();
        }

        public override string ToString()
        {
            string ret = $"{TriggerType} {Action} {SubTypeDescription}";
            if (CustomData.Any())
            {
                ret = $"{ret} {string.Join(",", CustomData.Select(d => d.Data))}";
            }
            return ret;
        }

        /// <summary>
        /// Trigger the service.
        /// </summary>
        public virtual void Trigger()
        {
            throw new NotImplementedException("This trigger type is not supported");
        }

        internal static ServiceTriggerInformation GetTriggerInformation(SERVICE_TRIGGER trigger)
        {
            if (trigger.dwTriggerType == ServiceTriggerType.Custom)
            {
                return new EtwServiceTriggerInformation(trigger);
            }
            else if (trigger.dwTriggerType == ServiceTriggerType.CustomSystemStateChange)
            {
                return new WnfServiceTriggerInformation(trigger);
            }
            return new ServiceTriggerInformation(trigger);
        }
    }
#pragma warning restore
}
