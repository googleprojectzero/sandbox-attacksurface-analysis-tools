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

    /// <summary>
    /// Class representing an NT object type
    /// </summary>
    public class NtType
    {
        /// <summary>
        /// The name of the type
        /// </summary>
        public string Name { get; private set; }
        /// <summary>
        /// The mapping from generic to specific object rights
        /// </summary>
        public GenericMapping GenericMapping { get; private set; }
        /// <summary>
        /// The valid access mask
        /// </summary>
        public uint ValidAccess { get; private set; }
        /// <summary>
        /// True if the object needs security even if unnamed
        /// </summary>
        public bool SecurityRequired { get; private set; }
        /// <summary>
        /// Total number of objects (when originally retrieved)
        /// </summary>
        public uint TotalNumberOfObjects { get; private set; }
        /// <summary>
        /// Total number of handles (when originally retrieved)
        /// </summary>
        public uint TotalNumberOfHandles { get; private set; }
        /// <summary>
        /// Total paged pool usage (when originally retrieved)
        /// </summary>
        public uint TotalPagedPoolUsage { get; private set; }
        /// <summary>
        /// Total non-paged pool usage (when originally retrieved)
        /// </summary>
        public uint TotalNonPagedPoolUsage { get; private set; }
        /// <summary>
        /// Total name pool usage (when originally retrieved)
        /// </summary>
        public uint TotalNamePoolUsage { get; private set; }
        /// <summary>
        /// Total handle table usage (when originally retrieved)
        /// </summary>
        public uint TotalHandleTableUsage { get; private set; }
        /// <summary>
        /// Maximum number of objects (when originally retrieved)
        /// </summary>
        public uint HighWaterNumberOfObjects { get; private set; }
        /// <summary>
        /// Maximum number of handles (when originally retrieved)
        /// </summary>
        public uint HighWaterNumberOfHandles { get; private set; }
        /// <summary>
        /// Maximum paged pool usage (when originally retrieved)
        /// </summary>
        public uint HighWaterPagedPoolUsage { get; private set; }
        /// <summary>
        /// Maximum non-paged pool usage (when originally retrieved)
        /// </summary>
        public uint HighWaterNonPagedPoolUsage { get; private set; }
        /// <summary>
        /// Maximum name pool usage (when originally retrieved)
        /// </summary>
        public uint HighWaterNamePoolUsage { get; private set; }
        /// <summary>
        /// Maximum handle table usage (when originally retrieved)
        /// </summary>
        public uint HighWaterHandleTableUsage { get; private set; }
        /// <summary>
        /// The attributes flags which are invalid
        /// </summary>
        public AttributeFlags InvalidAttributes { get; private set; }
        /// <summary>
        /// Indicates whether handle count is mainted
        /// </summary>
        public bool MaintainHandleCount { get; private set; }
        /// <summary>
        /// Indicates the type list maintained
        /// </summary>
        public ushort MaintainTypeList { get; private set; }
        /// <summary>
        /// Indicates the type of pool used in allocations
        /// </summary>
        public PoolType PoolType { get; private set; }
        /// <summary>
        /// Current paged pool usage
        /// </summary>
        public uint PagedPoolUsage { get; private set; }
        /// <summary>
        /// Current non-pages pool usage
        /// </summary>
        public uint NonPagedPoolUsage { get; private set; }
        /// <summary>
        /// Type Index
        /// </summary>
        public int Index { get; private set; }

        /// <summary>
        /// Checks if a access mask represents a read permission on this type
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it has read permissions</returns>
        public bool HasReadPermission(uint access_mask)
        {
            access_mask = GenericMapping.MapMask(access_mask);
            return (access_mask & GenericMapping.GenericRead) != 0;
        }

        /// <summary>
        /// Checks if a access mask represents a write permission on this type
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it has write permissions</returns>
        public bool HasWritePermission(uint access_mask)
        {
            access_mask = GenericMapping.MapMask(access_mask);
            return (access_mask & GenericMapping.GenericWrite & ~GenericMapping.GenericRead & ~GenericMapping.GenericExecute) != 0;
        }

        /// <summary>
        /// Checks if a access mask represents a execute permission on this type
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it has execute permissions</returns>
        public bool HasExecutePermission(uint access_mask)
        {
            access_mask = GenericMapping.MapMask(access_mask);
            return (access_mask & GenericMapping.GenericExecute & ~GenericMapping.GenericRead) != 0;
        }

        /// <summary>
        /// Checks if a access mask represents a full permission on this type
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it has full permissions</returns>
        public bool HasFullPermission(uint access_mask)
        {
            access_mask = GenericMapping.MapMask(access_mask);
            return (access_mask & GenericMapping.GenericAll) == GenericMapping.GenericAll;
        }

        /// <summary>
        /// Map generic access rights to specific access rights for this type
        /// </summary>
        /// <param name="access_mask">The access mask to map</param>
        /// <returns>The mapped access mask</returns>
        public uint MapGenericRights(uint access_mask)
        {
            return GenericMapping.MapMask(access_mask);
        }

        internal NtType(int id, ObjectTypeInformation info)
        {
            Index = id;
            Name = info.Name.ToString();
            InvalidAttributes = info.InvalidAttributes;
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
            MaintainHandleCount = info.MaintainHandleCount != 0;
            MaintainTypeList = info.MaintainTypeList;
            PoolType = info.PoolType;
            PagedPoolUsage = info.PagedPoolUsage;
            NonPagedPoolUsage = info.NonPagedPoolUsage;
        }

        private static Dictionary<string, NtType> _types;

        /// <summary>
        /// Get a type object by index
        /// </summary>
        /// <param name="index">The index</param>
        /// <returns>The object type, null if not found</returns>
        public static NtType GetTypeByIndex(int index)
        {
            foreach (NtType info in GetTypes())
            {
                if (info.Index == index)
                    return info;
            }

            return null;
        }

        /// <summary>
        /// Get a type object by name
        /// </summary>
        /// <param name="name">The name of the type</param>
        /// <returns>The object type, null if not found</returns>
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

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>Returns the type as a string.</returns>
        public override string ToString()
        {
            return String.Format("Name = {0} - Index = {1}", Name, Index);
        }

        /// <summary>
        /// Get a list of all types.
        /// </summary>
        /// <returns>The list of types.</returns>
        public static IEnumerable<NtType> GetTypes()
        {
            LoadTypes();
            return _types.Values;
        }
    }
}
