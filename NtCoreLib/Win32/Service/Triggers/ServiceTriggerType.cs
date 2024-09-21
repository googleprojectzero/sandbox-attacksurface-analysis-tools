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

using NtCoreLib.Utilities.Reflection;

namespace NtCoreLib.Win32.Service.Triggers;
#pragma warning disable 1591
/// <summary>
/// Service trigger type.
/// </summary>
public enum ServiceTriggerType
{
    [SDKName("SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL")]
    DeviceInterfaceArrival = 1,
    [SDKName("SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY")]
    IPAddressAvailability = 2,
    [SDKName("SERVICE_TRIGGER_TYPE_DOMAIN_JOIN")]
    DomainJoin = 3,
    [SDKName("SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT")]
    FirewallPortEvent = 4,
    [SDKName("SERVICE_TRIGGER_TYPE_GROUP_POLICY")]
    GroupPolicy = 5,
    [SDKName("SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT")]
    NetworkEndpoint = 6,
    [SDKName("SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE")]
    CustomSystemStateChange = 7,
    [SDKName("SERVICE_TRIGGER_TYPE_CUSTOM")]
    Custom = 20,
    [SDKName("SERVICE_TRIGGER_TYPE_AGGREGATE")]
    Aggregate = 30,
}
