//  Copyright 2018 Google Inc. All Rights Reserved.
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
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNet.Ndr
{
    /// <summary>
    /// Class to build text strings for an NDR formatter.
    /// </summary>
    public class NdrStringBuilder
    {
        private StringBuilder _builder = new StringBuilder();
        private Stack<string> _current_indent = new Stack<string>();
        private bool _new_line = true;

        #region Private Methods
        private void AppendIndent()
        {
            if (!_new_line)
            {
                return;
            }
            foreach (string s in _current_indent)
            {
                _builder.Append(s);
            }
            _new_line = false;
        }
        #endregion

        /// <summary>
        /// Push an indent string on to the indent stack.
        /// </summary>
        /// <param name="indent">The string to indent any new lines.</param>
        /// <returns>The current builder instance.</returns>
        public NdrStringBuilder PushIndent(string indent)
        {
            _current_indent.Push(indent);
            return this;
        }

        /// <summary>
        /// Push an indent on to the indent stack.
        /// </summary>
        /// <param name="ch">The character to indent with.</param>
        /// <param name="count">The number of indent characters.</param>
        /// <returns>The current builder instance.</returns>
        public NdrStringBuilder PushIndent(char ch, int count)
        {
            return PushIndent(new string(ch, count));
        }

        /// <summary>
        /// Pop the current indent off the indent stack.
        /// </summary>
        /// <returns>The current builder instance.</returns>
        public NdrStringBuilder PopIndent()
        {
            _current_indent.Pop();
            return this;
        }

        /// <summary>
        /// Append a string to the builder.
        /// </summary>
        /// <param name="str">The string to append.</param>
        /// <returns>The current builder instance.</returns>
        public NdrStringBuilder Append(string str)
        {
            AppendIndent();
            _builder.Append(str);
            return this;
        }

        /// <summary>
        /// Append a formatted string to the builder.
        /// </summary>
        /// <param name="format">The string format.</param>
        /// <param name="args">The array of arguments to the formatter.</param>
        /// <returns>The current builder instance.</returns>
        public NdrStringBuilder Append(string format, params object[] args)
        {
           return Append(string.Format(format, args));
        }

        /// <summary>
        /// Append a new line to the builder.
        /// </summary>
        /// <returns>The current builder instance.</returns>
        public NdrStringBuilder AppendLine()
        {
            return AppendLine(string.Empty);
        }

        /// <summary>
        /// Append a string to the builder with a new line.
        /// </summary>
        /// <param name="str">The string to append.</param>
        /// <returns>The current builder instance.</returns>
        public NdrStringBuilder AppendLine(string str)
        {
            Append(str);
            _builder.AppendLine();
            _new_line = true;
            return this;
        }

        /// <summary>
        /// Append a formatted string to the builder with a new line.
        /// </summary>
        /// <param name="format">The string format.</param>
        /// <param name="args">The array of arguments to the formatter.</param>
        /// <returns>The current builder instance.</returns>
        public NdrStringBuilder AppendLine(string format, params object[] args)
        {
            return AppendLine(string.Format(format, args));
        }

        /// <summary>
        /// Overridden ToString method, returns the current state of the builder.
        /// </summary>
        /// <returns>The current stated of the builder.</returns>
        public override string ToString()
        {
            return _builder.ToString();
        }
    }
}
