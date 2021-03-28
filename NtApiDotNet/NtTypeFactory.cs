//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.Reflection;

namespace NtApiDotNet
{
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
    internal sealed class NtTypeAttribute : Attribute
    {
        public string TypeName { get; }
        public bool DisableOpen { get; set; }
        public NtTypeAttribute(string type_name)
        {
            TypeName = type_name;
        }
    }

    internal abstract class NtFakeTypeFactory
    {
        public abstract IEnumerable<NtType> CreateTypes();

        public static IEnumerable<NtFakeTypeFactory> GetAssemblyFakeTypes(Assembly assembly)
        {
            return assembly.GetTypes().Where(t => t.IsClass && !t.IsAbstract 
                && typeof(NtFakeTypeFactory).IsAssignableFrom(t)).Select(t => (NtFakeTypeFactory)Activator.CreateInstance(t));
        }
    }

    internal class NtTypeFactory
    {
        private const string FACTORY_TYPE_NAME = "NtTypeFactoryImpl";
        private readonly IEnumerable<Enum> _query_info_class;
        private readonly IEnumerable<Enum> _set_info_class;

        private static IEnumerable<Enum> GetEnumValues(Type enum_type)
        {
            if (enum_type == null)
                return new Enum[0];
            if (!enum_type.IsEnum)
                throw new ArgumentException("Information class type must be an enumerated value.");

            return Enum.GetValues(enum_type).Cast<Enum>().ToList().AsReadOnly();
        }

        public Type ObjectType { get; }
        public Type AccessRightsType { get; }
        public Type ContainerAccessRightsType { get; }
        public bool CanOpen { get; private set; }
        public MandatoryLabelPolicy DefaultMandatoryPolicy { get; }

        public virtual IEnumerable<Enum> GetQueryInfoClass()
        {
            return _query_info_class;
        }
        public virtual IEnumerable<Enum> GetSetInfoClass()
        {
            return _set_info_class;
        }

        public virtual NtObject FromHandle(SafeKernelObjectHandle handle)
        {
            throw new NotImplementedException();
        }

        public virtual NtResult<NtObject> Open(ObjectAttributes obj_attributes, AccessMask desired_access, bool throw_on_error)
        {
            return NtStatus.STATUS_NOT_IMPLEMENTED.CreateResultFromError<NtObject>(throw_on_error);
        }

        internal NtTypeFactory(Type access_rights_type, Type container_access_rights_type, Type object_type, bool can_open, MandatoryLabelPolicy default_policy)
            : this(access_rights_type, container_access_rights_type, object_type, can_open, default_policy, null, null)
        {
        }

        internal NtTypeFactory(Type access_rights_type, Type container_access_rights_type, Type object_type, bool can_open, 
            MandatoryLabelPolicy default_policy, Type query_info_class_type, Type set_info_class_type) 
            
        {
            AccessRightsType = access_rights_type;
            ContainerAccessRightsType = container_access_rights_type;
            ObjectType = object_type;
            CanOpen = can_open;
            DefaultMandatoryPolicy = default_policy;
            _query_info_class = GetEnumValues(query_info_class_type);
            _set_info_class = GetEnumValues(set_info_class_type);
        }

        public static Dictionary<string, NtTypeFactory> GetAssemblyNtTypeFactories(Assembly assembly)
        {
            Dictionary<string, NtTypeFactory> factories = new Dictionary<string, NtTypeFactory>(StringComparer.OrdinalIgnoreCase);
            foreach (Type type in assembly.GetTypes().Where(t => t.IsClass && !t.IsAbstract && typeof(NtObject).IsAssignableFrom(t)))
            {
                IEnumerable<NtTypeAttribute> attrs = type.GetCustomAttributes<NtTypeAttribute>(false);
                foreach (NtTypeAttribute attr in attrs)
                {
                    System.Diagnostics.Debug.Assert(!factories.ContainsKey(attr.TypeName));
                    TypeInfo factory_type = type.GetTypeInfo().GetDeclaredNestedType(FACTORY_TYPE_NAME);
                    System.Diagnostics.Debug.Assert(factory_type != null);
                    var factory = (NtTypeFactory)Activator.CreateInstance(factory_type);
                    if (attr.DisableOpen)
                        factory.CanOpen = false;
                    factories.Add(attr.TypeName, factory);
                }
            }
            return factories;
        }
    }
}
