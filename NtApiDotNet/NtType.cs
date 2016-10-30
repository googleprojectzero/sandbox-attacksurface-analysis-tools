//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    /// <summary>
    /// Native structure used for getting type information.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectTypeInformation
    {
        public UnicodeStringOut Name;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;
        public uint HighWaterNumberOfHandles;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public AttributeFlags InvalidAttributes;
        public GenericMapping GenericMapping;
        public uint ValidAccess;
        public byte SecurityRequired;
        public byte MaintainHandleCount;
        public ushort MaintainTypeList;
        public PoolType PoolType;
        public uint PagedPoolUsage;
        public uint NonPagedPoolUsage;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectAllTypesInformation
    {
        public int NumberOfTypes;
        //ObjectTypeInformation TypeInformation; // Type Info list
    }
#pragma warning restore 1591

    public class NtType
    {
        public string Name { get; private set; }
        public AttributeFlags InvalidAttribute { get; private set; }
        public GenericMapping GenericMapping { get; private set; }
        public uint ValidAccess { get; private set; }
        public bool SecurityRequired { get; private set; }

        public uint TotalNumberOfObjects { get; private set; }
        public uint TotalNumberOfHandles { get; private set; }
        public uint TotalPagedPoolUsage { get; private set; }
        public uint TotalNonPagedPoolUsage { get; private set; }
        public uint TotalNamePoolUsage { get; private set; }
        public uint TotalHandleTableUsage { get; private set; }
        public uint HighWaterNumberOfObjects { get; private set; }
        public uint HighWaterNumberOfHandles { get; private set; }
        public uint HighWaterPagedPoolUsage { get; private set; }
        public uint HighWaterNonPagedPoolUsage { get; private set; }
        public uint HighWaterNamePoolUsage { get; private set; }
        public uint HighWaterHandleTableUsage { get; private set; }
        public AttributeFlags InvalidAttributes { get; private set; }

        public byte MaintainHandleCount { get; private set; }
        public ushort MaintainTypeList { get; private set; }
        public PoolType PoolType { get; private set; }
        public uint PagedPoolUsage { get; private set; }
        public uint NonPagedPoolUsage { get; private set; }

        public int Index { get; private set; }

        public bool HasReadPermission(uint access_mask)
        {
            access_mask = GenericMapping.MapMask(access_mask);
            return (access_mask & GenericMapping.GenericRead) != 0;
        }

        public bool HasWritePermission(uint access_mask)
        {
            access_mask = GenericMapping.MapMask(access_mask);
            return (access_mask & GenericMapping.GenericWrite & ~GenericMapping.GenericRead & ~GenericMapping.GenericExecute) != 0;
        }

        public bool HasExecutePermission(uint access_mask)
        {
            access_mask = GenericMapping.MapMask(access_mask);
            return (access_mask & GenericMapping.GenericExecute & ~GenericMapping.GenericRead) != 0;
        }

        public bool HasFullPermission(uint access_mask)
        {
            access_mask = GenericMapping.MapMask(access_mask);
            return (access_mask & GenericMapping.GenericAll) == GenericMapping.GenericAll;
        }

        public uint MapGenericRights(uint access_mask)
        {
            return GenericMapping.MapMask(access_mask);
        }

        internal NtType(int id, ObjectTypeInformation info)
        {
            Index = id;
            Name = info.Name.ToString();
            InvalidAttribute = info.InvalidAttributes;
            GenericMapping = info.GenericMapping;
            ValidAccess = info.ValidAccess;
            SecurityRequired = info.SecurityRequired != 0;

            TotalNumberOfObjects = info.TotalNumberOfObjects;
            TotalNumberOfHandles = info.TotalNumberOfHandles;
            TotalPagedPoolUsage = info.TotalPagedPoolUsage;
            TotalNonPagedPoolUsage = info.TotalNonPagedPoolUsage;
            TotalNamePoolUsage = info.TotalNamePoolUsage;
            TotalHandleTableUsage = info.TotalHandleTableUsage;
            HighWaterNumberOfObjects = info.HighWaterNumberOfObjects;
            HighWaterNumberOfHandles = info.HighWaterNumberOfHandles;
            HighWaterPagedPoolUsage = info.HighWaterPagedPoolUsage;
            HighWaterNonPagedPoolUsage = info.HighWaterNonPagedPoolUsage;
            HighWaterNamePoolUsage = info.HighWaterNamePoolUsage;
            HighWaterHandleTableUsage = info.HighWaterHandleTableUsage;
            InvalidAttributes = info.InvalidAttributes;
            MaintainHandleCount = info.MaintainHandleCount;
            MaintainTypeList = info.MaintainTypeList;
            PoolType = info.PoolType;
            PagedPoolUsage = info.PagedPoolUsage;
            NonPagedPoolUsage = info.NonPagedPoolUsage;
        }

        private static Dictionary<string, NtType> _types;

        public static NtType GetTypeByIndex(int index)
        {
            foreach (NtType info in GetTypes())
            {
                if (info.Index == index)
                    return info;
            }

            return null;
        }

        public static NtType GetTypeByName(string name)
        {
            LoadTypes();
            if (_types.ContainsKey(name))
            {
                return _types[name];
            }
            else
            {
                return null;
            }
        }

        private static void LoadTypes()
        {
            if (_types == null)
            {
                SafeStructureInOutBuffer<ObjectAllTypesInformation> type_info = new SafeStructureInOutBuffer<ObjectAllTypesInformation>();

                try
                {
                    Dictionary<string, NtType> ret = new Dictionary<string, NtType>(StringComparer.OrdinalIgnoreCase);
                    int return_length;
                    NtStatus status = NtSystemCalls.NtQueryObject(SafeKernelObjectHandle.Null, ObjectInformationClass.ObjectAllInformation,
                        type_info.DangerousGetHandle(), type_info.Length, out return_length);
                    if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                        status.ToNtException();

                    type_info.Close();
                    type_info = null;
                    type_info = new SafeStructureInOutBuffer<ObjectAllTypesInformation>(return_length, false);

                    int alignment = IntPtr.Size - 1;
                    NtSystemCalls.NtQueryObject(SafeKernelObjectHandle.Null, ObjectInformationClass.ObjectAllInformation,
                        type_info.DangerousGetHandle(), type_info.Length, out return_length).ToNtException();
                    ObjectAllTypesInformation result = type_info.Result;
                    IntPtr curr_typeinfo = type_info.DangerousGetHandle() + IntPtr.Size;
                    for (int count = 0; count < result.NumberOfTypes; ++count)
                    {
                        ObjectTypeInformation info = (ObjectTypeInformation)Marshal.PtrToStructure(curr_typeinfo, typeof(ObjectTypeInformation));
                        NtType ti = new NtType(count + 2, info);
                        ret[ti.Name] = ti;

                        int offset = (info.Name.MaximumLength + alignment) & ~alignment;
                        curr_typeinfo = info.Name.Buffer + offset;
                    }

                    _types = ret;
                }
                finally
                {
                    if (type_info != null)
                    {
                        type_info.Close();
                    }
                }
            }

        }

        public static IEnumerable<NtType> GetTypes()
        {
            LoadTypes();
            return _types.Values;
        }
    }
}
