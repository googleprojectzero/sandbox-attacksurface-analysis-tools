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

using NtApiDotNet.Ndr.Marshal;
using NtApiDotNet.Net.Sockets;
using NtApiDotNet.Utilities.Text;
using System;
using System.Diagnostics;

namespace NtApiDotNet.Win32.Rpc
{
    /// <summary>
    /// Some addition internal utilities for RPC code.
    /// </summary>
    public static class RpcUtils
    {
        internal static TraceSwitch RpcTraceSwitch = new TraceSwitch("RpcTrace", "RPC Tracing");

        /// <summary>
        /// Specify RPC trace level.
        /// </summary>
        /// <param name="level">Specify the RPC trace level.</param>
        /// <remarks>This dumps NDR data. Verbose dumps the binary data.</remarks>
        public static void SetRpcTraceLevel(TraceLevel level)
        {
            RpcTraceSwitch.Level = level;
        }

        internal static TraceSwitch RpcTransportTraceSwitch = new TraceSwitch("RpcTransportTrace", "RPC Transport Tracing");

        /// <summary>
        /// Specify RPC transport trace level.
        /// </summary>
        /// <param name="level">Specify the RPC transport trace level.</param>
        /// <remarks>Verbose dumps the transport binary data.</remarks>
        public static void SetRpcTransportTraceLevel(TraceLevel level)
        {
            RpcTransportTraceSwitch.Level = level;
        }

        private static bool CheckSwitch(bool transport)
        {
            var trace_switch = transport ? RpcTransportTraceSwitch : RpcTraceSwitch;
            return trace_switch.TraceVerbose;
        }

        internal static void DumpBuffer(bool transport, string title, byte[] buffer)
        {
            if (!CheckSwitch(transport))
                return;
            Trace.WriteLine($"{title}:");
            HexDumpBuilder builder = new HexDumpBuilder(true, true, true, true, 0);
            builder.Append(buffer);
            builder.Complete();
            Trace.WriteLine(builder.ToString());
        }

        internal static void DumpBuffer(bool transport, string title, AlpcMessage message)
        {
            if (!CheckSwitch(transport))
                return;
            using (var buffer = message.ToSafeBuffer())
            {
                DumpBuffer(transport, title, buffer.ToArray());
            }
        }

        /// <summary>
        /// Helper to dereference a type.
        /// </summary>
        /// <typeparam name="T">The type to dereference.</typeparam>
        /// <param name="t">The value to dereference.</param>
        /// <returns>The dereferenced result.</returns>
        public static T DeRef<T>(T t)
        {
            return t;
        }

        /// <summary>
        /// Helper to dereference a type.
        /// </summary>
        /// <typeparam name="T">The type to dereference.</typeparam>
        /// <param name="t">The value to dereference.</param>
        /// <returns>The dereferenced result.</returns>
        public static T DeRef<T>(T? t) where T : struct
        {
            return t.Value;
        }

        /// <summary>
        /// Helper to check for NULL.
        /// </summary>
        /// <typeparam name="T">The type to check.</typeparam>
        /// <param name="obj">The object to check.</param>
        /// <param name="name">The name of the value to check.</param>
        /// <returns>The checked value.</returns>
        public static T CheckNull<T>(T obj, string name) where T : class
        {
            if (obj == null)
            {
                throw new ArgumentNullException(name);
            }
            return obj;
        }

        /// <summary>
        /// Helper to check for NULL.
        /// </summary>
        /// <typeparam name="T">The type to check.</typeparam>
        /// <param name="obj">The object to check.</param>
        /// <param name="name">The name of the value to check.</param>
        /// <returns>The checked value.</returns>
        public static T[] CheckNull<T>(T[] obj, string name)
        {
            if (obj == null)
            {
                throw new ArgumentNullException(name);
            }
            return obj;
        }

        /// <summary>
        /// Helper to check for NULL.
        /// </summary>
        /// <typeparam name="T">The type to check.</typeparam>
        /// <param name="obj">The object to check.</param>
        /// <param name="name">The name of the value to check.</param>
        /// <returns>The checked value.</returns>
        public static T CheckNull<T>(T? obj, string name) where T : struct
        {
            if (!obj.HasValue)
            {
                throw new ArgumentNullException(name);
            }
            return obj.Value;
        }

        /// <summary>
        /// Helper to dereference a type.
        /// </summary>
        /// <typeparam name="T">The type to dereference.</typeparam>
        /// <param name="t">The value to dereference.</param>
        /// <returns>The dereferenced result.</returns>
        public static T DeRef<T>(NdrEmbeddedPointer<T> t) 
        {
            return t.GetValue();
        }

        /// <summary>
        /// Helper to perform a plus unary operation.
        /// </summary>
        /// <param name="v">The value to apply the operator to.</param>
        /// <returns>The result.</returns>
        public static long OpPlus(long v)
        {
            return +v;
        }

        /// <summary>
        /// Helper to perform a minus unary operation.
        /// </summary>
        /// <param name="v">The value to apply the operator to.</param>
        /// <returns>The result.</returns>
        public static long OpMinus(long v)
        {
            return -v;
        }

        /// <summary>
        /// Helper to perform a complement unary operation.
        /// </summary>
        /// <param name="v">The value to apply the operator to.</param>
        /// <returns>The result.</returns>
        public static long OpComplement(long v)
        {
            return ~v;
        }

        /// <summary>
        /// Perform a ternary operation.
        /// </summary>
        /// <param name="condition">The condition to evaluate as != 0.</param>
        /// <param name="true_value">The result if true.</param>
        /// <param name="false_value">The result if false.</param>
        /// <returns>The result.</returns>
        public static int OpTernary(bool condition, long true_value, long false_value)
        {
            return (int)(condition ? true_value : false_value);
        }

        /// <summary>
        /// Perform ADD.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpPlus(long left, long right)
        {
            return (int)(left + right);
        }

        /// <summary>
        /// Perform SUB.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpMinus(long left, long right)
        {
            return (int)(left - right);
        }

        /// <summary>
        /// Perform MUL.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpStar(long left, long right)
        {
            return (int)(left * right);
        }

        /// <summary>
        /// Perform DIV.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpSlash(long left, long right)
        {
            return (int)(left / right);
        }

        /// <summary>
        /// Perform MOD.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpMod(long left, long right)
        {
            return (int)(left % right);
        }

        /// <summary>
        /// Perform Bitwise AND.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpBitwiseAnd(long left, long right)
        {
            return (int)(left & right);
        }

        /// <summary>
        /// Perform Bitwise OR.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpBitwiseOr(long left, long right)
        {
            return (int)(left | right);
        }

        /// <summary>
        /// Perform bitwise XOR. Needed as Code DOM doesn't support XOR.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpXor(long left, long right)
        {
            return (int)(left ^ right);
        }

        /// <summary>
        /// Perform bitwise LEFTSHIFT.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpLeftShift(long left, long right)
        {
            return (int)(left << (int)right);
        }

        /// <summary>
        /// Perform bitwise RIGHTSHIFT.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpRightShift(long left, long right)
        {
            return (int)(left >> (int)right);
        }

        /// <summary>
        /// Perform logical AND.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpLogicalAnd(long left, long right)
        {
            return ToInt(ToBool(left) && ToBool(right));
        }

        /// <summary>
        /// Perform logical OR.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpLogicalOr(long left, long right)
        {
            return ToInt(ToBool(left) || ToBool(right));
        }

        /// <summary>
        /// Perform EQUAL.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpEqual(long left, long right)
        {
            return ToInt(left == right);
        }

        /// <summary>
        /// Perform NOTEQUAL.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpNotEqual(long left, long right)
        {
            return ToInt(left != right);
        }

        /// <summary>
        /// Perform GREATER.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpGreater(long left, long right)
        {
            return ToInt(left > right);
        }

        /// <summary>
        /// Perform GREATEREQUAL.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpGreaterEqual(long left, long right)
        {
            return ToInt(left >= right);
        }

        /// <summary>
        /// Perform LESS.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>The result.</returns>
        public static int OpLess(long left, long right)
        {
            return ToInt(left < right);
        }

        /// <summary>
        /// Perform LESSEQUAL.
        /// </summary>
        /// <param name="left">The left operand.</param>
        /// <param name="right">The right operand.</param>
        /// <returns>Returns left LESSEQUAL right.</returns>
        public static int OpLessEqual(long left, long right)
        {
            return ToInt(left <= right);
        }

        private static int ToInt(bool b)
        {
            return b ? 1 : 0;
        }

        /// <summary>
        /// Convert value to a boolean.
        /// </summary>
        /// <param name="value">The value</param>
        /// <returns>True if value != 0.</returns>
        public static bool ToBool(bool value)
        {
            return value;
        }

        /// <summary>
        /// Convert value to a boolean.
        /// </summary>
        /// <param name="value">The value</param>
        /// <returns>True if value != 0.</returns>
        public static bool ToBool(sbyte value)
        {
            return value != 0;
        }

        /// <summary>
        /// Convert value to a boolean.
        /// </summary>
        /// <param name="value">The value</param>
        /// <returns>True if value != 0.</returns>
        public static bool ToBool(byte value)
        {
            return value != 0;
        }

        /// <summary>
        /// Convert value to a boolean.
        /// </summary>
        /// <param name="value">The value</param>
        /// <returns>True if value != 0.</returns>
        public static bool ToBool(short value)
        {
            return value != 0;
        }

        /// <summary>
        /// Convert value to a boolean.
        /// </summary>
        /// <param name="value">The value</param>
        /// <returns>True if value != 0.</returns>
        public static bool ToBool(ushort value)
        {
            return value != 0;
        }

        /// <summary>
        /// Convert value to a boolean.
        /// </summary>
        /// <param name="value">The value</param>
        /// <returns>True if value != 0.</returns>
        public static bool ToBool(int value)
        {
            return value != 0;
        }

        /// <summary>
        /// Convert value to a boolean.
        /// </summary>
        /// <param name="value">The value</param>
        /// <returns>True if value != 0.</returns>
        public static bool ToBool(uint value)
        {
            return value != 0;
        }

        /// <summary>
        /// Convert value to a boolean.
        /// </summary>
        /// <param name="value">The value</param>
        /// <returns>True if value != 0.</returns>
        public static bool ToBool(long value)
        {
            return value != 0;
        }

        /// <summary>
        /// Convert value to a boolean.
        /// </summary>
        /// <param name="value">The value</param>
        /// <returns>True if value != 0.</returns>
        public static bool ToBool(ulong value)
        {
            return value != 0;
        }

        /// <summary>
        /// Convert value to a boolean.
        /// </summary>
        /// <param name="value">The nullable value</param>
        /// <returns>True if value has a value set.</returns>
        public static bool ToBool<T>(T? value) where T : struct
        {
            return value.HasValue;
        }

        /// <summary>
        /// Convert value to a boolean.
        /// </summary>
        /// <param name="value">The nullable value</param>
        /// <returns>True if value has a value set.</returns>
        public static bool ToBool<T>(T value) where T : class
        {
            return value != null;
        }

        /// <summary>
        /// Compose a string binding from its parts.
        /// </summary>
        /// <param name="objuuid">The object UUID.</param>
        /// <param name="protseq">The protocol sequence.</param>
        /// <param name="networkaddr">The network address.</param>
        /// <param name="endpoint">The endpoint.</param>
        /// <param name="options">The options.</param>
        /// <returns>The composed binding string.</returns>
        [Obsolete("Use RpcStringBinding class.")]
        public static string ComposeStringBinding(string objuuid, string protseq, string networkaddr,
            string endpoint, string options)
        {
            return new RpcStringBinding(protseq, networkaddr, endpoint, options, objuuid).ToString();
        }

        internal static Guid ResolveVmId(string guid)
        {
            if (string.IsNullOrEmpty(guid))
                return HyperVSocketGuids.HV_GUID_LOOPBACK;

            switch (guid.ToLower())
            {
                case "parent":
                    return HyperVSocketGuids.HV_GUID_PARENT;
                case "children":
                    return HyperVSocketGuids.HV_GUID_CHILDREN;
                case "silohost":
                    return HyperVSocketGuids.HV_GUID_SILOHOST;
                case "loopback":
                    return HyperVSocketGuids.HV_GUID_LOOPBACK;
                default:
                    return Guid.Parse(guid);
            }
        }
    }
}
