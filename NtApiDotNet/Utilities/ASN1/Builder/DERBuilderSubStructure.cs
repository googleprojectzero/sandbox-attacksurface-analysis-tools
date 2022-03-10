//  Copyright 2021 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Utilities.ASN1.Builder
{
    /// <summary>
    /// A DER builder for a sub-structure..
    /// </summary>
    /// <remarks>You should call Close or dispose the builder to write the sub-structure.</remarks>
    public sealed class DERBuilderSubStructure : DERBuilder, IDisposable
    {
        private readonly Action<DERBuilder> _write_value;
        private bool _is_closed;

        internal DERBuilderSubStructure(Action<DERBuilder> write_value)
        {
            _write_value = write_value;
        }

        /// <summary>
        /// Close the builder and write its contents to the parent builder.
        /// </summary>
        public void Close()
        {
            if (_is_closed)
                throw new ObjectDisposedException("DERBuilder");
            _is_closed = true;
            _write_value(this);
        }

        void IDisposable.Dispose()
        {
            if (!_is_closed)
            {
                Close();
            }
        }
    }
}
