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

using Microsoft.Win32.SafeHandles;
using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SandboxAnalysisUtils
{
    public enum ServiceTriggerType
    {
        DeviceInterfaceArrival = 1,
        IPAddressAvailability = 2,
        DomainJoin = 3,
        FirewallPortEvent = 4,
        GroupPolicy = 5,
        NetworkEndpoint = 6,
        CustomSystemStateChange = 7,
        Custom = 20,
        Aggregate = 30,
    }

    public enum ServiceTriggerDataType
    {
        Binary = 1,
        String = 2,
        Level = 3,
        KeywordAny = 4,
        KeywordAll = 5,
    }

    public enum ServiceTriggerAction
    {
        Start = 1,
        Stop = 2
    }

    [Flags]
        public enum ServiceControlManagerAccessRights : uint
        {
            CreateService = 0x0002,
            Connect = 0x0001,
            EnumerateService = 0x0004,
            Lock = 0x0008,
            ModifyBootConfig = 0x0020,
            QueryLockStatus = 0x0010,
            All = CreateService | Connect | EnumerateService
                | Lock | ModifyBootConfig | QueryLockStatus | ReadControl
                | Delete | WriteDac | WriteOwner,
            GenericRead = GenericAccessRights.GenericRead,
            GenericWrite = GenericAccessRights.GenericWrite,
            GenericExecute = GenericAccessRights.GenericExecute,
            GenericAll = GenericAccessRights.GenericAll,
            Delete = GenericAccessRights.Delete,
            ReadControl = GenericAccessRights.ReadControl,
            WriteDac = GenericAccessRights.WriteDac,
            WriteOwner = GenericAccessRights.WriteOwner,
            Synchronize = GenericAccessRights.Synchronize,
            MaximumAllowed = GenericAccessRights.MaximumAllowed,
            AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
        }

        [Flags]
        public enum ServiceAccessRights : uint
        {
            ChangeConfig = 0x0002,
            EnumerateDependents = 0x0008,
            Interrogate = 0x0080,
            PauseContinue = 0x0040,
            QueryConfig = 0x0001,
            QueryStatus = 0x0004,
            Start = 0x0010,
            Stop = 0x0020,
            UserDefinedControl = 0x0100,
            All = ChangeConfig | EnumerateDependents | Interrogate | PauseContinue
                | QueryStatus | QueryConfig | Start | Stop | UserDefinedControl | ReadControl
                | Delete | WriteDac | WriteOwner,
            GenericRead = GenericAccessRights.GenericRead,
            GenericWrite = GenericAccessRights.GenericWrite,
            GenericExecute = GenericAccessRights.GenericExecute,
            GenericAll = GenericAccessRights.GenericAll,
            Delete = GenericAccessRights.Delete,
            ReadControl = GenericAccessRights.ReadControl,
            WriteDac = GenericAccessRights.WriteDac,
            WriteOwner = GenericAccessRights.WriteOwner,
            Synchronize = GenericAccessRights.Synchronize,
            MaximumAllowed = GenericAccessRights.MaximumAllowed,
            AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
        }

    internal class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        [DllImport("Advapi32.dll", SetLastError = true)]
        static extern bool CloseServiceHandle(IntPtr hSCObject);

        public SafeServiceHandle() : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return CloseServiceHandle(handle);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_TRIGGER_INFO
    {
        public int cTriggers;
        public IntPtr pTriggers;
        public IntPtr pReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_TRIGGER
    {
        public ServiceTriggerType dwTriggerType;
        public ServiceTriggerAction dwAction;
        public IntPtr pTriggerSubtype;
        public int cDataItems;
        public IntPtr pDataItems;

        public Guid GetSubType()
        {
            if (pTriggerSubtype != IntPtr.Zero)
            {
                return (Guid)Marshal.PtrToStructure(pTriggerSubtype, typeof(Guid));
            }
            return Guid.Empty;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SERVICE_TRIGGER_SPECIFIC_DATA_ITEM
    {
        public ServiceTriggerDataType dwDataType;
        public int cbData;
        public IntPtr pData;
    }

    public class ServiceTriggerCustomData
    {
        public ServiceTriggerDataType DataType { get; private set; }
        public byte[] RawData { get; private set; }
        public string Data { get; private set; }

        private string GetDataString()
        {
            switch (DataType)
            {
                case ServiceTriggerDataType.Level:
                    if (RawData.Length == 1)
                    {
                        return String.Format("0x{0:X02}", RawData[0]);
                    }
                    break;
                case ServiceTriggerDataType.KeywordAny:
                case ServiceTriggerDataType.KeywordAll:
                    if (RawData.Length == 8)
                    {
                        return String.Format("0x{0:X016}", BitConverter.ToUInt64(RawData, 0));
                    }
                    break;
                case ServiceTriggerDataType.String:
                    if ((RawData.Length & 1) == 0)
                    {
                        string[] ss = Encoding.Unicode.GetString(RawData).TrimEnd('\0').Split('\0');
                        if (ss.Length == 1)
                        {
                           return ss[0];
                        }
                        else
                        {
                            return string.Join(", ", ss);
                        }
                    }
                    break;
            }
            return String.Join(",", RawData.Select(b => String.Format("0x{0:X02}", b)));
        }

        internal ServiceTriggerCustomData(SERVICE_TRIGGER_SPECIFIC_DATA_ITEM data_item)
        {
            DataType = data_item.dwDataType;
            RawData = new byte[data_item.cbData];
            if (data_item.pData != IntPtr.Zero)
            {
                Marshal.Copy(data_item.pData, RawData, 0, data_item.cbData);   
            }
            else
            {
                RawData = new byte[0];
            }
            Data = GetDataString();
        }
    }

    public class ServiceTriggerInformation
    {
        public ServiceTriggerType TriggerType { get; private set; }
        public ServiceTriggerAction Action { get; private set; }
        public Guid SubType { get; private set; }
        public string SubTypeDescription { get; private set; }
        public IEnumerable<ServiceTriggerCustomData> CustomData { get; private set; }

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
                    return String.Format("[ETW UUID] {0:B}", SubType);
                case ServiceTriggerType.DeviceInterfaceArrival:
                    return String.Format("[Interface Class GUID] {0:B}", SubType);
                case ServiceTriggerType.GroupPolicy:
                    {
                        if (SubType == MACHINE_POLICY_PRESENT_GUID)
                        {
                            return String.Format("[Machine Policy Present]");
                        }
                        else if (SubType == USER_POLICY_PRESENT_GUID)
                        {
                            return String.Format("[User Policy Present]");
                        }
                        return String.Format("[Unknown Group Policy] {0:B}", SubType);
                    }
                case ServiceTriggerType.NetworkEndpoint:
                    {
                        if (SubType == RPC_INTERFACE_EVENT_GUID)
                        {
                            return String.Format("[RPC Interface]");
                        }
                        else if (SubType == NAMED_PIPE_EVENT_GUID)
                        {
                            return String.Format("[Named Pipe]");
                        }
                        return String.Format("[Unknown Network Endpoint] {0:B}", SubType);
                    }
                case ServiceTriggerType.DomainJoin:
                    {
                        if (SubType == DOMAIN_JOIN_GUID)
                        {
                            return String.Format("[Domain Join]");
                        }
                        else if (SubType == DOMAIN_LEAVE_GUID)
                        {
                            return String.Format("[Domain Leave]");
                        }
                        return String.Format("[Unknown Domain Join] {0:B}", SubType);
                    }
                case ServiceTriggerType.IPAddressAvailability:
                    {
                        if (SubType == NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID)
                        {
                            return String.Format("[First IP Address Available]");
                        }
                        else if (SubType == NETWORK_MANAGER_LAST_IP_ADDRESS_REMOVAL_GUID)
                        {
                            return String.Format("[Last IP Address Available]");
                        }
                        return String.Format("[Unknown IP Address Availability] {0:B}", SubType);
                    }
                default:
                    return String.Format("Unknown Trigger Type: {0} SubType: {1}", TriggerType, SubType);
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
                SERVICE_TRIGGER_SPECIFIC_DATA_ITEM[] data_items;
                ReadArray(trigger.pDataItems, trigger.cDataItems, out data_items);
                for (int i = 0; i < data_items.Length; ++i)
                {
                    data.Add(new ServiceTriggerCustomData(data_items[i]));
                }
            }
            CustomData = data.AsReadOnly();
        }
    }

    public class ServiceSecurityInformation
    {
        public string Name { get; private set; }
        public SecurityDescriptor SecurityDescriptor { get; private set; }
        public IEnumerable<ServiceTriggerInformation> Triggers { get; private set; }

        internal ServiceSecurityInformation(string name, SecurityDescriptor sd, IEnumerable<ServiceTriggerInformation> triggers)
        {
            Name = name;
            SecurityDescriptor = sd;
            Triggers = triggers;
        }
    }

    public static class ServiceUtils
    {
        const int SERVICE_CONFIG_TRIGGER_INFO = 8;

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeServiceHandle OpenSCManager(string lpMachineName, string lpDatabaseName, ServiceControlManagerAccessRights dwDesiredAccess);

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeServiceHandle OpenService(
              SafeServiceHandle hSCManager,
              string lpServiceName,
              ServiceAccessRights dwDesiredAccess
            );

        [DllImport("Advapi32.dll", SetLastError = true)]
        static extern bool QueryServiceObjectSecurity(SafeServiceHandle hService,
            SecurityInformation dwSecurityInformation,
            [Out] byte[] lpSecurityDescriptor,
            int cbBufSize,
            out int pcbBytesNeeded);

        [DllImport("Advapi32.dll", SetLastError = true)]
        static extern bool QueryServiceConfig2(
          SafeServiceHandle hService,
          int dwInfoLevel,
          SafeBuffer lpBuffer,
          int cbBufSize,
          out int pcbBytesNeeded
        );

        
        public static GenericMapping GetScmGenericMapping()
        {
            GenericMapping mapping = new GenericMapping();
            mapping.GenericRead = ServiceControlManagerAccessRights.ReadControl | ServiceControlManagerAccessRights.EnumerateService | ServiceControlManagerAccessRights.QueryLockStatus;
            mapping.GenericWrite = ServiceControlManagerAccessRights.ReadControl | ServiceControlManagerAccessRights.CreateService | ServiceControlManagerAccessRights.ModifyBootConfig;
            mapping.GenericExecute = ServiceControlManagerAccessRights.ReadControl | ServiceControlManagerAccessRights.Connect | ServiceControlManagerAccessRights.Lock;
            mapping.GenericAll = ServiceControlManagerAccessRights.All;
            return mapping;
        }

        public static GenericMapping GetServiceGenericMapping()
        {
            GenericMapping mapping = new GenericMapping();
            mapping.GenericRead = ServiceAccessRights.ReadControl | ServiceAccessRights.QueryConfig
                | ServiceAccessRights.QueryStatus | ServiceAccessRights.Interrogate | ServiceAccessRights.EnumerateDependents;
            mapping.GenericWrite = ServiceAccessRights.ReadControl | ServiceAccessRights.ChangeConfig;
            mapping.GenericExecute = ServiceAccessRights.ReadControl | ServiceAccessRights.Start
                | ServiceAccessRights.Stop | ServiceAccessRights.PauseContinue | ServiceAccessRights.UserDefinedControl;
            mapping.GenericAll = ServiceAccessRights.All;
            return mapping;
        }

        public static SecurityDescriptor GetScmSecurityDescriptor()
        {
            using (SafeServiceHandle scm = OpenSCManager(null, null,
                            ServiceControlManagerAccessRights.Connect | ServiceControlManagerAccessRights.ReadControl))
            {
                return GetServiceSecurityDescriptor(scm);
            }
        }

        static SecurityDescriptor GetServiceSecurityDescriptor(SafeServiceHandle handle)
        {
            int required = 0;
            byte[] sd = new byte[8192];
            if (!QueryServiceObjectSecurity(handle, SecurityInformation.AllBasic, sd, sd.Length, out required))
            {
                throw new Win32Exception();
            }

            return new SecurityDescriptor(sd);
        }

        static IEnumerable<ServiceTriggerInformation> GetTriggersForService(SafeServiceHandle service)
        {
            List<ServiceTriggerInformation> triggers = new List<ServiceTriggerInformation>();
            using (var buf = new SafeStructureInOutBuffer<SERVICE_TRIGGER_INFO>(8192, false))
            {
                int required = 0;
                if (!QueryServiceConfig2(service, SERVICE_CONFIG_TRIGGER_INFO, buf, 8192, out required))
                {
                    return triggers.AsReadOnly();
                }

                SERVICE_TRIGGER_INFO trigger_info = buf.Result;
                if (trigger_info.cTriggers == 0)
                {
                    return triggers.AsReadOnly();
                }

                SERVICE_TRIGGER[] trigger_arr;
                using (SafeHGlobalBuffer trigger_buffer = new SafeHGlobalBuffer(trigger_info.pTriggers, trigger_info.cTriggers * Marshal.SizeOf(typeof(SERVICE_TRIGGER)), false))
                {
                    trigger_arr = new SERVICE_TRIGGER[trigger_info.cTriggers];
                    trigger_buffer.ReadArray(0, trigger_arr, 0, trigger_arr.Length);
                }

                for (int i = 0; i < trigger_arr.Length; ++i)
                {
                    triggers.Add(new ServiceTriggerInformation(trigger_arr[i]));
                }

                return triggers.AsReadOnly();
            }
        }

        private static ServiceSecurityInformation GetServiceSecurityInformation(SafeServiceHandle scm, string name)
        {
            using (SafeServiceHandle service = OpenService(scm, name, ServiceAccessRights.QueryConfig | ServiceAccessRights.ReadControl))
            {
                if (service.IsInvalid)
                {
                    throw new Win32Exception();
                }

                return new ServiceSecurityInformation(name, GetServiceSecurityDescriptor(service), GetTriggersForService(service));
            }
        }
        
        public static ServiceSecurityInformation GetServiceSecurityInformation(string name)
        {
            using (SafeServiceHandle scm = OpenSCManager(null, null,
                            ServiceControlManagerAccessRights.Connect | ServiceControlManagerAccessRights.ReadControl))
            {
                if (scm.IsInvalid)
                {
                    throw new Win32Exception();
                }

                return GetServiceSecurityInformation(scm, name);
            }
        }
    }
}
