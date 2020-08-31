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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Reflection;

namespace NtApiDotNet.Win32.Device
{
    /// <summary>
    /// Class containing well known device interface class GUIDs.
    /// </summary>
    public static class DeviceInterfaceClassGuids
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        public static readonly Guid GUID_DEVINTERFACE_BRIGHTNESS = new Guid("FDE5BBA4-B3F9-46FB-BDAA-0728CE3100B4");
        public static readonly Guid GUID_DEVINTERFACE_CDCHANGER = new Guid("53F56312-B6BF-11D0-94F2-00A0C91EFB8B");
        public static readonly Guid GUID_DEVINTERFACE_CDROM = new Guid("53F56308-B6BF-11D0-94F2-00A0C91EFB8B");
        public static readonly Guid GUID_DEVINTERFACE_COMPORT = new Guid("86E0D1E0-8089-11D0-9CE4-08003E301F73");
        public static readonly Guid GUID_DEVINTERFACE_DISK = new Guid("53F56307-B6BF-11D0-94F2-00A0C91EFB8B");
        public static readonly Guid GUID_DEVINTERFACE_DISPLAY_ADAPTER = new Guid("5B45201D-F2F2-4F3B-85BB-30FF1F953599");
        public static readonly Guid GUID_DEVINTERFACE_FLOPPY = new Guid("53F56311-B6BF-11D0-94F2-00A0C91EFB8B");
        public static readonly Guid GUID_DEVINTERFACE_HID = new Guid("4D1E55B2-F16F-11CF-88CB-001111000030");
        public static readonly Guid GUID_DEVINTERFACE_I2C = new Guid("2564AA4F-DDDB-4495-B497-6AD4A84163D7");
        public static readonly Guid GUID_DEVINTERFACE_IMAGE = new Guid("6BDD1FC6-810F-11D0-BEC7-08002BE2092F");
        public static readonly Guid GUID_DEVINTERFACE_KEYBOARD = new Guid("884b96c3-56ef-11d1-bc8c-00a0c91405dd");
        public static readonly Guid GUID_DEVINTERFACE_MEDIUMCHANGER = new Guid("53F56310-B6BF-11D0-94F2-00A0C91EFB8B");
        public static readonly Guid GUID_DEVINTERFACE_MODEM = new Guid("2C7089AA-2E0E-11D1-B114-00C04FC2AAE4");
        public static readonly Guid GUID_DEVINTERFACE_MONITOR = new Guid("E6F07B5F-EE97-4a90-B076-33F57BF4EAA7");
        public static readonly Guid GUID_DEVINTERFACE_MOUSE = new Guid("378DE44C-56EF-11D1-BC8C-00A0C91405DD");
        public static readonly Guid GUID_DEVINTERFACE_NET = new Guid("CAC88484-7515-4C03-82E6-71A87ABAC361");
        public static readonly Guid GUID_DEVINTERFACE_OPM = new Guid("BF4672DE-6B4E-4BE4-A325-68A91EA49C09");
        public static readonly Guid GUID_DEVINTERFACE_PARALLEL = new Guid("97F76EF0-F883-11D0-AF1F-0000F800845C");
        public static readonly Guid GUID_DEVINTERFACE_PARCLASS = new Guid("811FC6A5-F728-11D0-A537-0000F8753ED1");
        public static readonly Guid GUID_DEVINTERFACE_PARTITION = new Guid("53F5630A-B6BF-11D0-94F2-00A0C91EFB8B");
        public static readonly Guid GUID_DEVINTERFACE_SERENUM_BUS_ENUMERATOR = new Guid("4D36E978-E325-11CE-BFC1-08002BE10318");
        public static readonly Guid GUID_DEVINTERFACE_SIDESHOW = new Guid("152E5811-FEB9-4B00-90F4-D32947AE1681");
        public static readonly Guid GUID_DEVINTERFACE_STORAGEPORT = new Guid("2ACCFE60-C130-11D2-B082-00A0C91EFB8B");
        public static readonly Guid GUID_DEVINTERFACE_TAPE = new Guid("53F5630B-B6BF-11D0-94F2-00A0C91EFB8B");
        public static readonly Guid GUID_DEVINTERFACE_USB_DEVICE = new Guid("A5DCBF10-6530-11D2-901F-00C04FB951ED");
        public static readonly Guid GUID_DEVINTERFACE_USB_HOST_CONTROLLER = new Guid("3ABF6F2D-71C4-462A-8A92-1E6861E6AF27");
        public static readonly Guid GUID_DEVINTERFACE_USB_HUB = new Guid("F18A0E88-C30C-11D0-8815-00A0C906BED8");
        public static readonly Guid GUID_DEVINTERFACE_VIDEO_OUTPUT_ARRIVAL = new Guid("1AD9E4F0-F88D-4360-BAB9-4C2D55E564CD");
        public static readonly Guid GUID_DEVINTERFACE_VOLUME = new Guid("53F5630D-B6BF-11D0-94F2-00A0C91EFB8B");
        public static readonly Guid GUID_DEVINTERFACE_WPD = new Guid("6AC27878-A6FA-4155-BA85-F98F491D4F33");
        public static readonly Guid GUID_DEVINTERFACE_WPD_PRIVATE = new Guid("BA0C718F-4DED-49B7-BDD3-FABE28661211");
        public static readonly Guid GUID_DEVINTERFACE_WRITEONCEDISK = new Guid("53F5630C-B6BF-11D0-94F2-00A0C91EFB8B");
        public static readonly Guid GUID_VIRTUAL_AVC_CLASS = new Guid("616EF4D0-23CE-446D-A568-C31EB01913D0");
        public static readonly Guid GUID_61883_CLASS = new Guid("7EBEFBC0-3200-11d2-B4C2-00A0C9697D07");
        public static readonly Guid KSCATEGORY_ACOUSTIC_ECHO_CANCEL = new Guid("BF963D80-C559-11D0-8A2B-00A0C9255AC1");
        public static readonly Guid KSCATEGORY_AUDI = new Guid("6994AD04-93EF-11D0-A3CC-00A0C9223196");
        public static readonly Guid KSCATEGORY_AUDIO_DEVICE = new Guid("FBF6F530-07B9-11D2-A71E-0000F8004788");
        public static readonly Guid KSCATEGORY_AUDIO_GFX = new Guid("9BAF9572-340C-11D3-ABDC-00A0C90AB16F");
        public static readonly Guid KSCATEGORY_AUDIO_SPLITTER = new Guid("9EA331FA-B91B-45F8-9285-BD2BC77AFCDE");
        public static readonly Guid KSCATEGORY_BDA_IP_SINK
        = new Guid("71985F4A-1CA1-11d3-9CC8-00C04F7971E0");
        public static readonly Guid KSCATEGORY_BDA_NETWORK_EPG
        = new Guid("71985F49-1CA1-11d3-9CC8-00C04F7971E0");
        public static readonly Guid KSCATEGORY_BDA_NETWORK_PROVIDER
        = new Guid("71985F4B-1CA1-11d3-9CC8-00C04F7971E0");
        public static readonly Guid KSCATEGORY_BDA_NETWORK_TUNER
        = new Guid("71985F48-1CA1-11d3-9CC8-00C04F7971E0");
        public static readonly Guid KSCATEGORY_BDA_RECEIVER_COMPONENT
        = new Guid("FD0A5AF4-B41D-11d2-9C95-00C04F7971E0");
        public static readonly Guid KSCATEGORY_BDA_TRANSPORT_INFORMATION
        = new Guid("A2E3074F-6C3D-11d3-B653-00C04F79498E");
        public static readonly Guid KSCATEGORY_BRIDGE
        = new Guid("085AFF00-62CE-11CF-A5D6-28DB04C10000");
        public static readonly Guid KSCATEGORY_CAPTURE
        = new Guid("65E8773D-8F56-11D0-A3B9-00A0C9223196");
        public static readonly Guid KSCATEGORY_CLOCK
        = new Guid("53172480-4791-11D0-A5D6-28DB04C10000");
        public static readonly Guid KSCATEGORY_COMMUNICATIONSTRANSFORM
        = new Guid("CF1DDA2C-9743-11D0-A3EE-00A0C9223196");
        public static readonly Guid KSCATEGORY_CROSSBAR
        = new Guid("A799A801-A46D-11D0-A18C-00A02401DCD4");
        public static readonly Guid KSCATEGORY_DATACOMPRESSOR
        = new Guid("1E84C900-7E70-11D0-A5D6-28DB04C10000");
        public static readonly Guid KSCATEGORY_DATADECOMPRESSOR
        = new Guid("2721AE20-7E70-11D0-A5D6-28DB04C10000");
        public static readonly Guid KSCATEGORY_DATATRANSFORM
        = new Guid("2EB07EA0-7E70-11D0-A5D6-28DB04C10000");
        public static readonly Guid KSCATEGORY_DRM_DESCRAMBLE
        = new Guid("FFBB6E3F-CCFE-4D84-90D9-421418B03A8E");
        public static readonly Guid KSCATEGORY_ENCODER
        = new Guid("19689BF6-C384-48fd-AD51-90E58C79F70B");
        public static readonly Guid KSCATEGORY_ESCALANTE_PLATFORM_DRIVER
        = new Guid("74F3AEA8-9768-11D1-8E07-00A0C95EC22E");
        public static readonly Guid KSCATEGORY_FILESYSTEM
        = new Guid("760FED5E-9357-11D0-A3CC-00A0C9223196");
        public static readonly Guid KSCATEGORY_INTERFACETRANSFORM
        = new Guid("CF1DDA2D-9743-11D0-A3EE-00A0C9223196");
        public static readonly Guid KSCATEGORY_MEDIUMTRANSFORM
        = new Guid("CF1DDA2E-9743-11D0-A3EE-00A0C9223196");
        public static readonly Guid KSCATEGORY_MICROPHONE_ARRAY_PROCESSOR
        = new Guid("830A44F2-A32D-476B-BE97-42845673B35A");
        public static readonly Guid KSCATEGORY_MIXER
        = new Guid("AD809C00-7B88-11D0-A5D6-28DB04C10000");
        public static readonly Guid KSCATEGORY_MULTIPLEXER
        = new Guid("7A5DE1D3-01A1-452c-B481-4FA2B96271E8");
        public static readonly Guid KSCATEGORY_NETWORK
        = new Guid("67C9CC3C-69C4-11D2-8759-00A0C9223196");
        public static readonly Guid KSCATEGORY_NETWORK_CAMERA
        = new Guid("B8238652-B500-41EB-B4F3-4234F7F5AE99");
        public static readonly Guid KSCATEGORY_PREFERRED_WAVEOUT_DEVICE
        = new Guid("D6C50674-72C1-11D2-9755-0000F8004788");
        public static readonly Guid KSCATEGORY_PREFERRED_WAVEIN_DEVICE
        = new Guid("D6C50671-72C1-11D2-9755-0000F8004788");
        public static readonly Guid KSCATEGORY_PROXY
        = new Guid("97EBAACA-95BD-11D0-A3EA-00A0C9223196");
        public static readonly Guid KSCATEGORY_QUALITY
        = new Guid("97EBAACB-95BD-11D0-A3EA-00A0C9223196");
        public static readonly Guid KSCATEGORY_REALTIME
        = new Guid("EB115FFC-10C8-4964-831D-6DCB02E6F23F");
        public static readonly Guid KSCATEGORY_RENDER
        = new Guid("65E8773E-8F56-11D0-A3B9-00A0C9223196");
        public static readonly Guid KSCATEGORY_SENSOR_CAMERA
        = new Guid("24E552D7-6523-47F7-A647-D3465BF1F5CA");
        public static readonly Guid KSCATEGORY_SPLITTER
        = new Guid("0A4252A0-7E70-11D0-A5D6-28DB04C10000");
        public static readonly Guid KSCATEGORY_SYNTHESIZER
        = new Guid("DFF220F3-F70F-11D0-B917-00A0C9223196");
        public static readonly Guid KSCATEGORY_SYSAUDIO
        = new Guid("A7C7A5B1-5AF3-11D1-9CED-00A024BF0407");
        public static readonly Guid KSCATEGORY_TEXT
        = new Guid("6994AD06-93EF-11D0-A3CC-00A0C9223196");
        public static readonly Guid KSCATEGORY_TOPOLOGY
        = new Guid("DDA54A40-1E4C-11D1-A050-405705C10000");
        public static readonly Guid KSCATEGORY_TVAUDIO
        = new Guid("A799A802-A46D-11D0-A18C-00A02401DCD4");
        public static readonly Guid KSCATEGORY_TVTUNER
        = new Guid("A799A800-A46D-11D0-A18C-00A02401DCD4");
        public static readonly Guid KSCATEGORY_VBICODEC
        = new Guid("07DAD660-22F1-11D1-A9F4-00C04FBBDE8F");
        public static readonly Guid KSCATEGORY_VIDEO
        = new Guid("6994AD05-93EF-11D0-A3CC-00A0C9223196");
        public static readonly Guid KSCATEGORY_VIDEO_CAMERA
        = new Guid("E5323777-F976-4f5b-9B55-B94699C46E44");
        public static readonly Guid KSCATEGORY_VIRTUAL
        = new Guid("3503EAC4-1F26-11D1-8AB0-00A0C9223196");
        public static readonly Guid KSCATEGORY_VPMUX
        = new Guid("A799A803-A46D-11D0-A18C-00A02401DCD4");
        public static readonly Guid KSCATEGORY_WDMAUD
        = new Guid("3E227E76-690D-11D2-8161-0000F8775BF1");
        public static readonly Guid KSMFT_CATEGORY_AUDIO_DECODER
        = new Guid("9ea73fb4-ef7a-4559-8d5d-719d8f0426c7");
        public static readonly Guid KSMFT_CATEGORY_AUDIO_EFFECT
        = new Guid("11064c48-3648-4ed0-932e-05ce8ac811b7");
        public static readonly Guid KSMFT_CATEGORY_AUDIO_ENCODER
        = new Guid("91c64bd0-f91e-4d8c-9276-db248279d975");
        public static readonly Guid KSMFT_CATEGORY_DEMULTIPLEXER
        = new Guid("a8700a7a-939b-44c5-99d7-76226b23b3f1");
        public static readonly Guid KSMFT_CATEGORY_MULTIPLEXER
        = new Guid("059c561e-05ae-4b61-b69d-55b61ee54a7b");
        public static readonly Guid KSMFT_CATEGORY_OTHER
        = new Guid("90175d57-b7ea-4901-aeb3-933a8747756f");
        public static readonly Guid KSMFT_CATEGORY_VIDEO_DECODER
        = new Guid("d6c02d4b-6833-45b4-971a-05a4b04bab91");
        public static readonly Guid KSMFT_CATEGORY_VIDEO_EFFECT
        = new Guid("12e17c21-532c-4a6e-8a1c-40825a736397");
        public static readonly Guid KSMFT_CATEGORY_VIDEO_ENCODER
        = new Guid("f79eac7d-e545-4387-bdee-d647d7bde42a");
        public static readonly Guid KSMFT_CATEGORY_VIDEO_PROCESSOR
        = new Guid("302ea3fc-aa5f-47f9-9f7a-c2188bb16302");
        public static readonly Guid GUID_DEVINTERFACE_SURFACE_VIRTUAL_DRIVE 
            = new Guid("2E34D650-5819-42CA-84AE-D30803BAE505");
        public static readonly Guid GUID_USBSTOR_EHSTOR_CONTROL_INTERFACE
            = new Guid("4f40006f-b933-4550-b532-2b58cee614d3");
        public static readonly Guid GUID_BTHPORT_DEVICE_INTERFACE
            = new Guid("0850302A-B344-4fda-9BE9-90576B8D46F0");
        public static readonly Guid GUID_HYPERV_VOLUME_CHECKPOINT_DEVICE_INTERFACE
            = new Guid("35fa2e29-ea23-4236-96ae-3a6ebacba440");
        public static readonly Guid GUID_HYPERV_SOCKET_DEVICE_INTERFACE
            = new Guid("999e53d4-3d5c-4c3e-8779-bed06ec056e1");
        public static readonly Guid VOLMGR_VOLUME_MANAGER_GUID 
            = new Guid("53f5630e-b6bf-11d0-94f2-00a0c91efb8b");

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member

        /// <summary>
        /// Convert interface class GUID to a string.
        /// </summary>
        /// <param name="interface_class_guid"></param>
        /// <returns>The name of the interface class GUID.</returns>
        public static string GuidToName(Guid interface_class_guid)
        {
            if (_guid_to_names == null)
            {
                PopulateDictionary();
            }
            return _guid_to_names.GetOrAdd(interface_class_guid, string.Empty);
        }

        private static void PopulateDictionary()
        {
            Dictionary<Guid, string> dict = new Dictionary<Guid, string>();
            foreach (var f in typeof(DeviceInterfaceClassGuids).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                if (f.FieldType == typeof(Guid))
                {
                    Guid key = (Guid)f.GetValue(null);
                    dict[key] = f.Name;
                }
            }
            _guid_to_names = new ConcurrentDictionary<Guid, string>(dict);
        }

        private static ConcurrentDictionary<Guid, string> _guid_to_names;
    }
}
