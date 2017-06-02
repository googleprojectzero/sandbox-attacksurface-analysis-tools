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
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Reflection;

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

    [AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
    internal sealed class NtTypeAttribute : Attribute
    {
        public string TypeName { get; private set; }
        public NtTypeAttribute(string type_name)
        {
            TypeName = type_name;
        }
    }

    internal sealed class NtTypeFactory
    {
        private MethodInfo _open_from_name_method;
        public Type ObjectType { get; private set; }
        public Type AccessRightsType { get; private set; }
        public bool CanOpen { get { return _open_from_name_method != null; } }
        public Func<SafeKernelObjectHandle, NtObject> FromHandle { get; private set; }

        public NtObject Open(string name, NtObject root, AccessMask desired_access)
        {
            try
            {
                return (NtObject)_open_from_name_method.Invoke(null, 
                    new object[] { name, root,
                        Enum.ToObject(AccessRightsType, desired_access.Access) });
            }
            catch (TargetInvocationException ex)
            {
                throw ex.InnerException;
            }
        }

        public NtTypeFactory(Type object_type)
        {
            Type base_type = object_type.BaseType;
            System.Diagnostics.Debug.Assert(base_type.GetGenericTypeDefinition() == typeof(NtObjectWithDuplicate<,>));
            ObjectType = object_type;
            MethodInfo from_handle_method = base_type.GetMethod("FromHandle", 
                BindingFlags.Public | BindingFlags.Static, 
                null, new Type[] { typeof(SafeKernelObjectHandle) }, null);
            FromHandle = (Func<SafeKernelObjectHandle, NtObject>)Delegate.CreateDelegate(typeof(Func<SafeKernelObjectHandle, NtObject>), from_handle_method);
            AccessRightsType = base_type.GetGenericArguments()[1];
            _open_from_name_method = object_type.GetMethod("Open", 
                BindingFlags.Public | BindingFlags.Static, null, 
                new Type[] { typeof(string), typeof(NtObject), AccessRightsType }, null);
            if (_open_from_name_method == null)
            {
                System.Diagnostics.Debug.WriteLine(String.Format("Type {0} doesn't have an open method", object_type));
            }
        }

        public static Dictionary<string, NtTypeFactory> GetAssemblyNtTypeFactories(Assembly assembly)
        {
            Dictionary<string, NtTypeFactory> _factories = new Dictionary<string, NtTypeFactory>(StringComparer.OrdinalIgnoreCase);
            foreach (Type type in assembly.GetTypes().Where(t => t.IsClass && !t.IsAbstract && typeof(NtObject).IsAssignableFrom(t)))
            {
                IEnumerable<NtTypeAttribute> attrs = type.GetCustomAttributes<NtTypeAttribute>();
                foreach (NtTypeAttribute attr in attrs)
                {
                    System.Diagnostics.Debug.Assert(!_factories.ContainsKey(attr.TypeName));
                    _factories.Add(attr.TypeName, new NtTypeFactory(type));
                }
            }
            return _factories;
        }
    }

#pragma warning restore 1591

    /// <summary>
    /// Class representing an NT object type
    /// </summary>
    public sealed class NtType
    {
        private static NtTypeFactory _generic_factory = new NtTypeFactory(typeof(NtGeneric));
        private NtTypeFactory _type_factory;

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
        public AccessMask ValidAccess { get; private set; }
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
        /// Get implemented object type for this NT type.
        /// </summary>
        public Type ObjectType
        {
            get
            {
                return _type_factory.ObjectType;
            }
        }

        /// <summary>
        /// Get the access rights enumerated type for this NT type.
        /// </summary>
        public Type AccessRightsType
        {
            get
            {
                return _type_factory.AccessRightsType;
            }
        }
        /// <summary>
        /// Can this type of open be opened by name
        /// </summary>
        public bool CanOpen
        {
            get { return _type_factory.CanOpen; }
        }

        /// <summary>
        /// Open this NT type by name (if CanOpen is true)
        /// </summary>
        /// <param name="name">The name of the object to open.</param>
        /// <param name="root">The root object for opening, if name is relative</param>
        /// <param name="desired_access">Desired access when opening.</param>
        /// <returns>The created object.</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtObject Open(string name, NtObject root, AccessMask desired_access)
        {
            if (!CanOpen)
            {
                throw new ArgumentException(String.Format("Can't open type {0} by name", Name));
            }           

            return _type_factory.Open(name, root, desired_access);
        }

        /// <summary>
        /// Open this NT type by name (if CanOpen is true)
        /// </summary>
        /// <param name="name">The name of the object to open.</param>
        /// <param name="root">The root object for opening, if name is relative</param>
        /// <returns>The created object.</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtObject Open(string name, NtObject root)
        {
            return Open(name, root, GenericAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open this NT type by name (if CanOpen is true)
        /// </summary>
        /// <param name="name">The name of the object to open.</param>
        /// <returns>The created object.</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public NtObject Open(string name)
        {
            return Open(name, null);
        }

        /// <summary>
        /// Get open from an existing handle.
        /// </summary>
        /// <param name="handle">The existing handle.</param>
        /// <returns>The new object.</returns>
        public NtObject FromHandle(SafeKernelObjectHandle handle)
        {
            return _type_factory.FromHandle(handle);
        }

        /// <summary>
        /// Convert an enumerable access rights to a string
        /// </summary>
        /// <param name="granted_access">The granted access mask.</param>
        /// <param name="map_to_generic">True to try and convert to generic rights where possible.</param>
        /// <returns>The string format of the access rights</returns>
        public string AccessMaskToString(AccessMask granted_access, bool map_to_generic)
        {
            return NtObjectUtils.GrantedAccessAsString(granted_access, GenericMapping, AccessRightsType, map_to_generic);
        }

        /// <summary>
        /// Convert an enumerable access rights to a string
        /// </summary>
        /// <param name="granted_access">The granted access mask.</param>
        /// <returns>The string format of the access rights</returns>
        public string AccessMaskToString(AccessMask granted_access)
        {
            return AccessMaskToString(granted_access, false);
        }

        /// <summary>
        /// Checks if an access mask represents a read permission on this type
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it has read permissions</returns>
        public bool HasReadPermission(AccessMask access_mask)
        {
            return GenericMapping.HasRead(access_mask);
        }

        /// <summary>
        /// Checks if an access mask represents a write permission on this type
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it has write permissions</returns>
        public bool HasWritePermission(AccessMask access_mask)
        {
            // We consider here that Delete, WriteDac and WriteOwner are also write permissions.
            if ((access_mask & (GenericAccessRights.WriteDac 
                                | GenericAccessRights.WriteOwner 
                                | GenericAccessRights.Delete)).HasAccess)
            {
                return true;
            }

            return GenericMapping.HasWrite(access_mask);
        }

        /// <summary>
        /// Checks if an access mask represents a execute permission on this type
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it has execute permissions</returns>
        public bool HasExecutePermission(AccessMask access_mask)
        {
            return GenericMapping.HasExecute(access_mask);
        }

        /// <summary>
        /// Checks if an access mask represents a full permission on this type
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it has full permissions</returns>
        public bool HasFullPermission(AccessMask access_mask)
        {
            return GenericMapping.HasAll(access_mask);
        }

        /// <summary>
        /// Map generic access rights to specific access rights for this type
        /// </summary>
        /// <param name="access_mask">The access mask to map</param>
        /// <returns>The mapped access mask</returns>
        public AccessMask MapGenericRights(AccessMask access_mask)
        {
            return GenericMapping.MapMask(access_mask);
        }

        /// <summary>
        /// Unmap specific access rights to generic access rights for this type
        /// </summary>
        /// <param name="access_mask">The access mask to unmap</param>
        /// <returns>The unmapped access mask</returns>
        public AccessMask UnmapGenericRights(AccessMask access_mask)
        {
            return GenericMapping.UnmapMask(access_mask);
        }

        /// <summary>
        /// Checks if an access mask is valid for access of this object type.
        /// </summary>
        /// <param name="access_mask">The access mask to check</param>
        /// <returns>True if it valid access</returns>
        public bool IsValidAccess(AccessMask access_mask)
        {
            return (GenericMapping.MapMask(access_mask) & ~ValidAccess).IsEmpty;
        }

        internal NtType(int id, string name)
        {
            Index = id;
            Name = name;
            if (Name == null)
            {
                Name = String.Format("Unknown {0}", id);
            }
            System.Diagnostics.Debug.WriteLine(String.Format("Generating Fake Type for {0}", Name));
            _type_factory = _generic_factory;
        }

        internal NtType(int id, ObjectTypeInformation info, NtTypeFactory type_factory)
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
            _type_factory = type_factory;
        }

        private static Dictionary<string, NtType> _types = LoadTypes();

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

            return new NtType(index, null);
        }

        /// <summary>
        /// Get a type object by name
        /// </summary>
        /// <param name="name">The name of the type</param>
        /// <returns>The object type, null if not found</returns>
        public static NtType GetTypeByName(string name)
        {
            if (_types.ContainsKey(name))
            {
                return _types[name];
            }
            
            return new NtType(-1, name);
        }

        /// <summary>
        /// Get an NT type based on the implemented .NET type.
        /// </summary>
        /// <typeparam name="T">A type derived from NtObject</typeparam>
        /// <returns>The NtType represented by this .NET type. Note if a type is represented with multiple
        /// names only return the first one we find.</returns>
        /// <exception cref="ArgumentException">Thrown if there exists no .NET type which maps to this type.</exception>
        public static NtType GetTypeByType<T>() where T : NtObject
        {
            IEnumerable<NtTypeAttribute> attrs = typeof(T).GetCustomAttributes<NtTypeAttribute>();
            if (attrs.Count() == 0)
            {
                throw new ArgumentException("Type has no mapping to an NT Type");
            }
            return GetTypeByName(attrs.First().TypeName);
        }

        private static Dictionary<string, NtType> LoadTypes()
        {
            var type_factories = NtTypeFactory.GetAssemblyNtTypeFactories(Assembly.GetExecutingAssembly());
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
                    string name = info.Name.ToString();
                    NtTypeFactory factory = type_factories.ContainsKey(name) ? type_factories[name] : _generic_factory;
                    NtType ti = new NtType(count + 2, info, factory);
                    ret[ti.Name] = ti;

                    int offset = (info.Name.MaximumLength + alignment) & ~alignment;
                    curr_typeinfo = info.Name.Buffer + offset;
                }

                return ret;
            }
            finally
            {
                if (type_info != null)
                {
                    type_info.Close();
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
            return _types.Values;
        }
    }
}
