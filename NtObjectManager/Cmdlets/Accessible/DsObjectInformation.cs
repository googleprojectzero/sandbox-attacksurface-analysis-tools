//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtCoreLib.Utilities.Security.Authorization;
using NtCoreLib.Win32.DirectoryService;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtObjectManager.Cmdlets.Accessible;

internal sealed class DsObjectInformation
{
    private struct ExtendedRightsComparer : IEqualityComparer<DirectoryServiceExtendedRight>
    {
        public bool Equals(DirectoryServiceExtendedRight x, DirectoryServiceExtendedRight y)
        {
            return x.RightsId == y.RightsId;
        }

        public int GetHashCode(DirectoryServiceExtendedRight obj)
        {
            return obj.RightsId.GetHashCode();
        }
    }

    private struct AttributeComparer : IEqualityComparer<DirectoryServiceSchemaAttribute>
    {
        public bool Equals(DirectoryServiceSchemaAttribute x, DirectoryServiceSchemaAttribute y)
        {
            return x.SchemaId == y.SchemaId;
        }

        public int GetHashCode(DirectoryServiceSchemaAttribute obj)
        {
            return obj.SchemaId.GetHashCode();
        }
    }

    public DirectoryServiceSchemaClass SchemaClass { get; private set; }
    public IReadOnlyList<DirectoryServiceSchemaClass> InferiorClasses { get; private set; }
    public IReadOnlyList<DirectoryServiceSchemaAttribute> Attributes { get; private set; }
    public IReadOnlyList<DirectoryServiceExtendedRight> ExtendedRights { get; private set; }
    public IEnumerable<DirectoryServiceExtendedRight> PropertySets => ExtendedRights.Where(r => r.IsPropertySet);
    public IEnumerable<DirectoryServiceExtendedRight> Control => ExtendedRights.Where(r => r.IsControl);
    public IEnumerable<DirectoryServiceExtendedRight> ValidatedWrite => ExtendedRights.Where(r => r.IsValidatedWrite);
    public Dictionary<Guid, IDirectoryServiceObjectTree> ObjectTypes { get; private set; }
    public HashSet<string> ClassNames { get; private set; }

    public ObjectTypeTree GetInferiorClasses()
    {
        ObjectTypeTree ret = DirectoryServiceUtils.DefaultPropertySet.ToObjectTypeTree();
        ret.AddNodeRange(InferiorClasses.Select(c => c.ToObjectTypeTree()));
        return ret;
    }

    public ObjectTypeTree GetAttributes(IEnumerable<DsObjectInformation> dynamic_aux_classes)
    {
        ObjectTypeTree ret = SchemaClass.ToObjectTypeTree();

        var prop_sets = dynamic_aux_classes.SelectMany(c => c.PropertySets).Concat(PropertySets).Distinct(new ExtendedRightsComparer());

        ret.AddNodeRange(prop_sets.Select(c => c.ToObjectTypeTree()));
        ObjectTypeTree unclass = DirectoryServiceUtils.DefaultPropertySet.ToObjectTypeTree();
        var attrs = dynamic_aux_classes.SelectMany(c => c.Attributes).Concat(Attributes).Distinct(new AttributeComparer());
        unclass.AddNodeRange(attrs.Where(a => !a.InPropertySet).Select(a => a.ToObjectTypeTree()));
        if (unclass.Nodes.Count > 0)
        {
            ret.AddNode(unclass);
        }
        return ret;
    }

    public ObjectTypeTree GetExtendedRights()
    {
        ObjectTypeTree ret = SchemaClass.ToObjectTypeTree();
        ret.AddNodeRange(Control.Select(c => c.ToObjectTypeTree()));
        ret.AddNodeRange(ValidatedWrite.Select(c => c.ToObjectTypeTree()));
        return ret;
    }

    private static List<DirectoryServiceSchemaAttribute> GetAttributes(string domain, string name)
    {
        List<DirectoryServiceSchemaAttribute> attrs = new();
        var schema_class = DirectoryServiceUtils.GetSchemaClass(domain, name);
        if (schema_class == null)
            return attrs;

        attrs.AddRange(schema_class.Attributes.Select(a => DirectoryServiceUtils.GetSchemaAttribute(domain, a.Name)));
        schema_class.AuxiliaryClasses.SelectMany(a => GetAttributes(domain, a.Name));
        if (schema_class.SubClassOf == null)
            return attrs;
        attrs.AddRange(GetAttributes(domain, schema_class.SubClassOf));
        return attrs;
    }

    private DsObjectInformation()
    {
    }

    private static void AddObjectTypes(Dictionary<Guid, IDirectoryServiceObjectTree> obj_types, IEnumerable<IDirectoryServiceObjectTree> objs)
    {
        foreach (var obj in objs)
        {
            obj_types[obj.Id] = obj;
        }
    }

    public static DsObjectInformation Get(string domain, string object_class)
    {
        var schema_class = DirectoryServiceUtils.GetSchemaClass(domain, object_class);
        if (schema_class == null)
            return null;
        var ret = new DsObjectInformation();
        ret.SchemaClass = schema_class;
        var classes = DirectoryServiceUtils.GetSchemaClasses(domain, object_class, true);
        ret.ClassNames = new HashSet<string>(classes.Select(c => c.Name));
        ret.InferiorClasses = schema_class.PossibleInferiors.Select(i => DirectoryServiceUtils.GetSchemaClass(domain, i)).ToList();
        ret.Attributes = classes.SelectMany(c => c.Attributes.Select(a => DirectoryServiceUtils.GetSchemaAttribute(domain, a.Name))).Distinct(new AttributeComparer()).ToList();
        ret.ExtendedRights = DirectoryServiceUtils.GetExtendedRights(domain, schema_class.SchemaId).Distinct(new ExtendedRightsComparer()).ToList();

        ret.ObjectTypes = new Dictionary<Guid, IDirectoryServiceObjectTree>();
        ret.ObjectTypes[ret.SchemaClass.SchemaId] = ret.SchemaClass;
        AddObjectTypes(ret.ObjectTypes, ret.InferiorClasses);
        AddObjectTypes(ret.ObjectTypes, ret.Attributes);
        AddObjectTypes(ret.ObjectTypes, ret.ExtendedRights);

        return ret;
    }
}
