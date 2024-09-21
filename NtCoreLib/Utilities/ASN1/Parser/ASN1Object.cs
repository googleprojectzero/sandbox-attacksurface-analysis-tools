//  Copyright 2022 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Utilities.ASN1.Builder;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Utilities.ASN1.Parser
{
    /// <summary>
    /// Base class for an ASN1 object.
    /// </summary>
    public abstract class ASN1Object : IDERObject
    {
        #region Private Members
        private void CheckConstructed()
        {
            if (!Constructed)
                throw new InvalidOperationException("Object is not constructed.");
        }

        private void CheckParent()
        {
            if (Parent is null)
                throw new InvalidOperationException("Object has no parent.");
        }

        private int GetChildIndex(ASN1Object child_obj)
        {
            int index = _children.IndexOf(child_obj);
            if (index < 0)
                throw new InvalidOperationException("Child object is not present.");
            return index;
        }
        #endregion
        #region Protected Members
        private protected readonly byte[] _data;
        private protected readonly List<ASN1Object> _children;

        private protected ASN1Object(DERValue value) : this((ASN1ObjectType)value.Type, value.Tag, 
            value.Constructed, value.HasChildren() ? value.Children.Select(ToObject) : Array.Empty<ASN1Object>(),
            value.Data)
        {
        }

        private protected ASN1Object(ASN1ObjectType object_type, int tag, bool constructed, IEnumerable<ASN1Object> children, byte[] data)
        {
            ObjectType = object_type;
            Tag = tag;
            Constructed = constructed;
            _children = children.ToList();
            _children.ForEach(c => c.Parent = this);
            _data = data;
        }

        private protected virtual string FormatTag()
        {
            return Tag.ToString();
        }

        private protected virtual string FormatValue()
        {
            return Constructed ? string.Empty : NtObjectUtils.ToHexString(_data);
        }

        private protected virtual void Format(StringBuilder builder, int depth)
        {
            builder.AppendFormat("{0}{1} {2} {3} {4}", new string(' ', depth * 2),
                ObjectType, Constructed, FormatTag(), FormatValue());
            builder.AppendLine();

            foreach (var c in Children)
            {
                c.Format(builder, depth + 1);
            }
        }

        #endregion

        #region Internal Members
        internal static ASN1Object ToObject(DERValue value)
        {
            switch (value.Type)
            {
                case DERTagType.Application:
                    return new ASN1Application(value);
                case DERTagType.ContextSpecific:
                    return new ASN1ContextSpecific(value);
                case DERTagType.Private:
                    return new ASN1Private(value);
                case DERTagType.Universal:
                    return ASN1Universal.ToObject(value);
            }
            return null;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The type of ASN.1 object.
        /// </summary>
        public ASN1ObjectType ObjectType { get; }

        /// <summary>
        /// The ASN.1 tag.
        /// </summary>
        public int Tag { get; }

        /// <summary>
        /// Whether this is a constructed type.
        /// </summary>
        public bool Constructed { get; }

        /// <summary>
        /// Get the child objects for the ASN1 data.
        /// </summary>
        public IReadOnlyCollection<ASN1Object> Children => _children.AsReadOnly();

        /// <summary>
        /// Get the ASN1 object's data.
        /// </summary>
        public byte[] Data => Constructed ? Array.Empty<byte>() : _data.CloneBytes();

        /// <summary>
        /// The parent object.
        /// </summary>
        public ASN1Object Parent { get; private set; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Format this object and any children.
        /// </summary>
        /// <returns>The formatted ASN1 objects.</returns>
        public string Format()
        {
            StringBuilder builder = new StringBuilder();
            Format(builder, 0);
            return builder.ToString();
        }

        /// <summary>
        /// Encode the object as a DER byte array.
        /// </summary>
        /// <returns>The object as a DER byte array.</returns>
        public byte[] ToArray()
        {
            DERBuilder builder = new DERBuilder();
            builder.WriteObject(this);
            return builder.ToArray();
        }

        /// <summary>
        /// Replace this object with another in the parent.
        /// </summary>
        /// <param name="new_obj">The object to replace with.</param>
        public void Replace(ASN1Object new_obj)
        {
            CheckParent();
            Parent.ReplaceChild(this, new_obj);
        }

        /// <summary>
        /// Detach this object from its parent.
        /// </summary>
        public void Detach()
        {
            if (Parent == null)
                return;
            Parent.RemoveChild(this);
        }

        /// <summary>
        /// Replace a child object with a new one.
        /// </summary>
        /// <param name="child_obj">The child object to replace.</param>
        /// <param name="new_obj">The new object to replace with.</param>
        public void ReplaceChild(ASN1Object child_obj, ASN1Object new_obj)
        {
            CheckConstructed();
            _children[GetChildIndex(child_obj)] = new_obj;
            child_obj.Parent = null;
        }

        /// <summary>
        /// Remove a child object.
        /// </summary>
        /// <param name="child_obj">The child object to remove.</param>
        public void RemoveChild(ASN1Object child_obj)
        {
            CheckConstructed();
            _children.RemoveAt(GetChildIndex(child_obj));
            child_obj.Parent = null;
        }

        /// <summary>
        /// Add a child object.
        /// </summary>
        /// <param name="child_obj">The child object to add.</param>
        public void AddChild(ASN1Object child_obj)
        {
            if (child_obj.Parent != null)
                throw new ArgumentException("Child object already has a parent.", nameof(child_obj));
            _children.Add(child_obj);
            child_obj.Parent = this;
        }

        /// <summary>
        /// Insert a child object at a specific index.
        /// </summary>
        /// <param name="index">The index to insert at.</param>
        /// <param name="child_obj">The child object to add.</param>
        public void InsertChild(int index, ASN1Object child_obj)
        {
            if (child_obj.Parent != null)
                throw new ArgumentException("Child object already has a parent.", nameof(child_obj));
            _children.Insert(index, child_obj);
            child_obj.Parent = this;
        }
        #endregion

        #region IDERObject Implementation
        void IDERObject.Write(DERBuilder builder)
        {
            if (Constructed)
            {
                builder.WriteTaggedValue((DERTagType)ObjectType, Constructed, Tag, Children);
            }
            else
            {
                builder.WriteTaggedValue((DERTagType)ObjectType, Constructed, Tag, _data);
            }
        }
        #endregion
    }
}
