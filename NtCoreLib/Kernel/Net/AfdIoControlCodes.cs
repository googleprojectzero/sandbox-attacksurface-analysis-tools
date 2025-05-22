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
//  Based on PH source https://github.com/winsiderss/systeminformer/blob/85723cfb22b03ed7c068bbe784385dd64551a14b/phnt/include/ntafd.h

namespace NtCoreLib.Kernel.Net;

internal static class AfdIoControlCodes
{
    public static readonly AfdIoControlCode IOCTL_AFD_BIND = new(0, FileControlMethod.Neither); // 0x12003
    public static readonly AfdIoControlCode IOCTL_AFD_CONNECT = new(1, FileControlMethod.Neither); // 0x12007
    public static readonly AfdIoControlCode IOCTL_AFD_START_LISTEN = new(2, FileControlMethod.Neither); // 0x1200B
    public static readonly AfdIoControlCode IOCTL_AFD_WAIT_FOR_LISTEN = new(3, FileControlMethod.Buffered); // 0x1200C
    public static readonly AfdIoControlCode IOCTL_AFD_ACCEPT = new(4, FileControlMethod.Buffered); // 0x12010
    public static readonly AfdIoControlCode IOCTL_AFD_RECEIVE = new(5, FileControlMethod.Neither); // 0x12017
    public static readonly AfdIoControlCode IOCTL_AFD_RECEIVE_DATAGRAM = new(6, FileControlMethod.Neither); // 0x1201B
    public static readonly AfdIoControlCode IOCTL_AFD_SEND = new(7, FileControlMethod.Neither); // 0x1201F
    public static readonly AfdIoControlCode IOCTL_AFD_SEND_DATAGRAM = new(8, FileControlMethod.Neither); // 0x12023
    public static readonly AfdIoControlCode IOCTL_AFD_POLL = new(9, FileControlMethod.Buffered); // 0x12024
    public static readonly AfdIoControlCode IOCTL_AFD_PARTIAL_DISCONNECT = new(10, FileControlMethod.Neither); // 0x1202B
    public static readonly AfdIoControlCode IOCTL_AFD_GET_ADDRESS = new(11, FileControlMethod.Neither); // 0x1202F
    public static readonly AfdIoControlCode IOCTL_AFD_QUERY_RECEIVE_INFO = new(12, FileControlMethod.Neither); // 0x12033
    public static readonly AfdIoControlCode IOCTL_AFD_QUERY_HANDLES = new(13, FileControlMethod.Neither); // 0x12037
    public static readonly AfdIoControlCode IOCTL_AFD_SET_INFORMATION = new(14, FileControlMethod.Neither); // 0x1203B
    public static readonly AfdIoControlCode IOCTL_AFD_GET_REMOTE_ADDRESS = new(15, FileControlMethod.Neither); // 0x1203F
    public static readonly AfdIoControlCode IOCTL_AFD_GET_CONTEXT = new(16, FileControlMethod.Neither); // 0x12043
    public static readonly AfdIoControlCode IOCTL_AFD_SET_CONTEXT = new(17, FileControlMethod.Neither); // 0x12047
    public static readonly AfdIoControlCode IOCTL_AFD_SET_CONNECT_DATA = new(18, FileControlMethod.Neither); // 0x1204B
    public static readonly AfdIoControlCode IOCTL_AFD_SET_CONNECT_OPTIONS = new(19, FileControlMethod.Neither); // 0x1204F
    public static readonly AfdIoControlCode IOCTL_AFD_SET_DISCONNECT_DATA = new(20, FileControlMethod.Neither); // 0x12053
    public static readonly AfdIoControlCode IOCTL_AFD_SET_DISCONNECT_OPTIONS = new(21, FileControlMethod.Neither); // 0x12057
    public static readonly AfdIoControlCode IOCTL_AFD_GET_CONNECT_DATA = new(22, FileControlMethod.Neither); // 0x1205B
    public static readonly AfdIoControlCode IOCTL_AFD_GET_CONNECT_OPTIONS = new(23, FileControlMethod.Neither); // 0x1205F
    public static readonly AfdIoControlCode IOCTL_AFD_GET_DISCONNECT_DATA = new(24, FileControlMethod.Neither); // 0x12063
    public static readonly AfdIoControlCode IOCTL_AFD_GET_DISCONNECT_OPTIONS = new(25, FileControlMethod.Neither); // 0x12067
    public static readonly AfdIoControlCode IOCTL_AFD_SIZE_CONNECT_DATA = new(26, FileControlMethod.Neither); // 0x1206B
    public static readonly AfdIoControlCode IOCTL_AFD_SIZE_CONNECT_OPTIONS = new(27, FileControlMethod.Neither); // 0x1206F
    public static readonly AfdIoControlCode IOCTL_AFD_SIZE_DISCONNECT_DATA = new(28, FileControlMethod.Neither); // 0x12073
    public static readonly AfdIoControlCode IOCTL_AFD_SIZE_DISCONNECT_OPTIONS = new(29, FileControlMethod.Neither); // 0x12077
    public static readonly AfdIoControlCode IOCTL_AFD_GET_INFORMATION = new(30, FileControlMethod.Neither); // 0x1207B
    public static readonly AfdIoControlCode IOCTL_AFD_TRANSMIT_FILE = new(31, FileControlMethod.Neither); // 0x1207F
    public static readonly AfdIoControlCode IOCTL_AFD_SUPER_ACCEPT = new(32, FileControlMethod.Neither); // 0x12083
    public static readonly AfdIoControlCode IOCTL_AFD_EVENT_SELECT = new(33, FileControlMethod.Neither); // 0x12087
    public static readonly AfdIoControlCode IOCTL_AFD_ENUM_NETWORK_EVENTS = new(34, FileControlMethod.Neither); // 0x1208B
    public static readonly AfdIoControlCode IOCTL_AFD_DEFER_ACCEPT = new(35, FileControlMethod.Buffered); // 0x1208C
    public static readonly AfdIoControlCode IOCTL_AFD_WAIT_FOR_LISTEN_LIFO = new(36, FileControlMethod.Buffered); // 0x12090
    public static readonly AfdIoControlCode IOCTL_AFD_SET_QOS = new(37, FileControlMethod.Buffered); // 0x12094
    public static readonly AfdIoControlCode IOCTL_AFD_GET_QOS = new(38, FileControlMethod.Buffered); // 0x12098
    public static readonly AfdIoControlCode IOCTL_AFD_NO_OPERATION = new(39, FileControlMethod.Neither); // 0x1209F
    public static readonly AfdIoControlCode IOCTL_AFD_VALIDATE_GROUP = new(40, FileControlMethod.Buffered); // 0x120A0
    public static readonly AfdIoControlCode IOCTL_AFD_GET_UNACCEPTED_CONNECT_DATA = new(41, FileControlMethod.Neither); // 0x120A7
    public static readonly AfdIoControlCode IOCTL_AFD_ROUTING_INTERFACE_QUERY = new(42, FileControlMethod.Neither); // 0x120AB
    public static readonly AfdIoControlCode IOCTL_AFD_ROUTING_INTERFACE_CHANGE = new(43, FileControlMethod.Buffered); // 0x120AC
    public static readonly AfdIoControlCode IOCTL_AFD_ADDRESS_LIST_QUERY = new(44, FileControlMethod.Neither); // 0x120B3
    public static readonly AfdIoControlCode IOCTL_AFD_ADDRESS_LIST_CHANGE = new(45, FileControlMethod.Buffered); // 0x120B4
    public static readonly AfdIoControlCode IOCTL_AFD_JOIN_LEAF = new(46, FileControlMethod.Neither); // 0x120BB
    public static readonly AfdIoControlCode IOCTL_AFD_TRANSPORT_IOCTL = new(47, FileControlMethod.Neither); // 0x120BF
    public static readonly AfdIoControlCode IOCTL_AFD_TRANSMIT_PACKETS = new(48, FileControlMethod.Neither); // 0x120C3
    public static readonly AfdIoControlCode IOCTL_AFD_SUPER_CONNECT = new(49, FileControlMethod.Neither); // 0x120C7
    public static readonly AfdIoControlCode IOCTL_AFD_SUPER_DISCONNECT = new(50, FileControlMethod.Neither); // 0x120CB
    public static readonly AfdIoControlCode IOCTL_AFD_RECEIVE_MESSAGE = new(51, FileControlMethod.Neither); // 0x120CF
    public static readonly AfdIoControlCode IOCTL_AFD_SEND_MESSAGE = new(52, FileControlMethod.Neither); // 0x120D3 // rev // since VISTA
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_CEMENT_SAN = new(53, FileControlMethod.Neither); // 0x120D7
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_SET_EVENTS = new(54, FileControlMethod.Neither); // 0x120DB
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_RESET_EVENTS = new(55, FileControlMethod.Neither); // 0x120DF
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_CONNECT_IND = new(56, FileControlMethod.OutDirect); // 0x120E2
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_CMPL_ACCEPT = new(57, FileControlMethod.Neither); // 0x120E7
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_CMPL_REQUEST = new(58, FileControlMethod.Neither); // 0x120EB
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_CMPL_IO = new(59, FileControlMethod.Neither); // 0x120EF
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_REFRESH_ENDP = new(60, FileControlMethod.Neither); // 0x120F3
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_GET_PHYSICAL_ADDR = new(61, FileControlMethod.Neither); // 0x120F7
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_ACQUIRE_CTX = new(62, FileControlMethod.Neither); // 0x120FB
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_TRANSFER_CTX = new(63, FileControlMethod.Neither); // 0x120FF
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_GET_SERVICE_PID = new(64, FileControlMethod.Neither); // 0x12103
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_SET_SERVICE_PROCESS = new(65, FileControlMethod.Neither); // 0x12107
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_PROVIDER_CHANGE = new(66, FileControlMethod.Neither); // 0x1210B
    public static readonly AfdIoControlCode IOCTL_AFD_SWITCH_ADDRLIST_CHANGE = new(67, FileControlMethod.Buffered); // 0x1210C
    public static readonly AfdIoControlCode IOCTL_AFD_UNBIND = new(68, FileControlMethod.Neither); // 0x12113 // rev
    public static readonly AfdIoControlCode IOCTL_AFD_SQM = new(69, FileControlMethod.Neither); // 0x12117 // rev // since WIN7
    public static readonly AfdIoControlCode IOCTL_AFD_RIO = new(70, FileControlMethod.Neither); // 0x1211B // rev // since WIN8
    public static readonly AfdIoControlCode IOCTL_AFD_TRANSFER_BEGIN = new(71, FileControlMethod.Neither); // 0x1211F // rev // since TH1
    public static readonly AfdIoControlCode IOCTL_AFD_TRANSFER_END = new(72, FileControlMethod.Neither); // 0x12123 // rev
    public static readonly AfdIoControlCode IOCTL_AFD_NOTIFY = new(73, FileControlMethod.Neither); // 0x12127 // rev // since 22H2
}
