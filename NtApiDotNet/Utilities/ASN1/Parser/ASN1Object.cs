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

using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Utilities.ASN1.Parser
{
    /// <summary>
    /// Base class for an ASN1 object.
    /// </summary>
    public abstract class ASN1Object
    {
        #region Protected Members
        private protected DERValue _value;

        private protected ASN1Object(DERValue value)
        {
            _value = value;
            List<ASN1Object> children = new List<ASN1Object>();
            if (_value.HasChildren())
            {
                children.AddRange(_value.Children.Select(ToObject));
            }
            Children = children.AsReadOnly();
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
                    return new ASN1Universal(value);
            }
            return null;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get the child objects for the ASN1 data.
        /// </summary>
        public IReadOnlyCollection<ASN1Object> Children { get; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Format this object and any children.
        /// </summary>
        /// <returns>The formatted ASN1 objects.</returns>
        public string Format()
        {
            return ASN1Utils.FormatDER(new[] { _value }, 0);
        }
        #endregion
    }
}
