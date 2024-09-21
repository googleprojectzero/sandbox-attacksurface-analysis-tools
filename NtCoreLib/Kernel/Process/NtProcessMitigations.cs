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

namespace NtCoreLib.Kernel.Process;

#pragma warning disable 1591

/// <summary>
/// Class representing various process mitigations
/// </summary>
public sealed class NtProcessMitigations
{
    internal NtProcessMitigations(NtProcess process)
    {
        ProcessDepStatus dep_status = process.DepStatus;
        DisableAtlThunkEmulation = dep_status.DisableAtlThunkEmulation;
        DepEnabled = dep_status.Enabled;
        DepPermanent = dep_status.Permanent;

        int result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.ASLR);
        EnableBottomUpRandomization = result.GetBit(0);
        EnableForceRelocateImages = result.GetBit(1);
        EnableHighEntropy = result.GetBit(2);
        DisallowStrippedImages = result.GetBit(3);

        DisallowWin32kSystemCalls = process.GetRawMitigationPolicy(ProcessMitigationPolicy.SystemCallDisable).GetBit(0);
        AuditDisallowWin32kSystemCalls = process.GetRawMitigationPolicy(ProcessMitigationPolicy.SystemCallDisable).GetBit(1);
        DisallowFsctlSystemCalls = process.GetRawMitigationPolicy(ProcessMitigationPolicy.SystemCallDisable).GetBit(2);
        AuditDisallowFsctlSystemCalls = process.GetRawMitigationPolicy(ProcessMitigationPolicy.SystemCallDisable).GetBit(3);

        result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.StrictHandleCheck);
        RaiseExceptionOnInvalidHandleReference = result.GetBit(0);
        HandleExceptionsPermanentlyEnabled = result.GetBit(1);

        result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.FontDisable);
        DisableNonSystemFonts = result.GetBit(0);
        AuditNonSystemFontLoading = result.GetBit(1);

        result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.DynamicCode);
        ProhibitDynamicCode = result.GetBit(0);
        AllowThreadOptOut = result.GetBit(1);
        AllowRemoteDowngrade = result.GetBit(2);
        AuditProhibitDynamicCode = result.GetBit(3);

        DisableExtensionPoints = process.GetRawMitigationPolicy(ProcessMitigationPolicy.ExtensionPointDisable).GetBit(0);

        result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.ControlFlowGuard);
        EnabledControlFlowGuard = result.GetBit(0);
        EnableExportSuppression = result.GetBit(1);
        ControlFlowGuardStrictMode = result.GetBit(2);

        result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.Signature);
        MicrosoftSignedOnly = result.GetBit(0);
        StoreSignedOnly = result.GetBit(1);
        SignedMitigationOptIn = result.GetBit(2);
        AuditMicrosoftSignedOnly = result.GetBit(3);
        AuditStoreSignedOnly = result.GetBit(4);

        result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.ImageLoad);
        NoRemoteImages = result.GetBit(0);
        NoLowMandatoryLabelImages = result.GetBit(1);
        PreferSystem32Images = result.GetBit(2);
        AuditNoRemoteImages = result.GetBit(3);
        AuditNoLowMandatoryLabelImages = result.GetBit(4);

        SystemCallFilterId = process.GetRawMitigationPolicy(ProcessMitigationPolicy.SystemCallFilter) & 0xF;

        NoChildProcessCreation = process.IsChildProcessRestricted;
        result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.ChildProcess);
        AuditNoChildProcessCreation = result.GetBit(1);
        AllowSecureProcessCreation = result.GetBit(2);

        result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.PayloadRestriction);
        EnableExportAddressFilter     = result.GetBit(0);
        AuditExportAddressFilter      = result.GetBit(1);
        EnableExportAddressFilterPlus = result.GetBit(2);
        AuditExportAddressFilterPlus  = result.GetBit(3);
        EnableImportAddressFilter     = result.GetBit(4);
        AuditImportAddressFilter      = result.GetBit(5);
        EnableRopStackPivot           = result.GetBit(6);
        AuditRopStackPivot            = result.GetBit(7);
        EnableRopCallerCheck          = result.GetBit(8);
        AuditRopCallerCheck           = result.GetBit(9);
        EnableRopSimExec              = result.GetBit(10);
        AuditRopSimExec               = result.GetBit(11);

        result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.SideChannelIsolation);
        SmtBranchTargetIsolation = result.GetBit(0);
        IsolateSecurityDomain = result.GetBit(1);
        DisablePageCombine = result.GetBit(2);
        SpeculativeStoreBypassDisable = result.GetBit(3);

        result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.UserShadowStack);
        EnableUserShadowStack = result.GetBit(0);
        AuditUserShadowStack = result.GetBit(1);
        SetContextIpValidation = result.GetBit(2);
        AuditSetContextIpValidation = result.GetBit(3);
        EnableUserShadowStackStrictMode = result.GetBit(4);
        BlockNonCetBinaries = result.GetBit(5);
        BlockNonCetBinariesNonEhcont = result.GetBit(6);
        AuditBlockNonCetBinaries = result.GetBit(7);
        CetDynamicApisOutOfProcOnly = result.GetBit(8);
        SetContextIpValidationRelaxedMode = result.GetBit(9);

        result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.RedirectionTrust);
        EnforceRedirectionTrust = result.GetBit(0);
        AuditRedirectionTrust = result.GetBit(1);

        using (var token = NtToken.OpenProcessToken(process, TokenAccessRights.Query, false))
        {
            if (token.IsSuccess)
            {
                IsRestricted = token.Result.Restricted;
                IsAppContainer = token.Result.AppContainer;
                IsLowPrivilegeAppContainer = token.Result.LowPrivilegeAppContainer;
                IntegrityLevel = token.Result.IntegrityLevel;
            }
        }
        ProcessId = process.ProcessId;
        Name = process.Name;
        ImagePath = process.FullPath;
        Win32ImagePath = process.Win32ImagePath;
        CommandLine = process.CommandLine;
    }

    public int ProcessId { get; }
    public string Name { get; }
    public string ImagePath { get; }
    public string Win32ImagePath { get; }
    public string CommandLine { get; }
    public bool IsRestricted { get; }
    public bool IsAppContainer { get; }
    public bool IsLowPrivilegeAppContainer { get; }
    public TokenIntegrityLevel IntegrityLevel { get; }

    public bool DisallowWin32kSystemCalls { get; }
    public bool AuditDisallowWin32kSystemCalls { get; }
    public bool DisallowFsctlSystemCalls { get; }
    public bool AuditDisallowFsctlSystemCalls { get; }
    public bool DepEnabled { get; }
    public bool DisableAtlThunkEmulation { get; }
    public bool DepPermanent { get; }
    public bool EnableBottomUpRandomization { get; }
    public bool EnableForceRelocateImages { get; }
    public bool EnableHighEntropy { get; }
    public bool DisallowStrippedImages { get; }
    public bool RaiseExceptionOnInvalidHandleReference { get; }
    public bool HandleExceptionsPermanentlyEnabled { get; }
    public bool DisableNonSystemFonts { get; }
    public bool AuditNonSystemFontLoading { get; }
    public bool ProhibitDynamicCode { get; }
    public bool DisableExtensionPoints { get; }
    public bool EnabledControlFlowGuard { get; }
    public bool EnableExportSuppression { get; }
    public bool ControlFlowGuardStrictMode { get; }
    public bool MicrosoftSignedOnly { get; }
    public bool StoreSignedOnly { get; }
    public bool SignedMitigationOptIn { get; }
    public bool AuditMicrosoftSignedOnly { get; }
    public bool AuditStoreSignedOnly { get; }
    public bool NoRemoteImages { get; }
    public bool NoLowMandatoryLabelImages { get; }
    public bool PreferSystem32Images { get; }
    public bool AuditNoRemoteImages { get; }
    public bool AuditNoLowMandatoryLabelImages { get; }
    public int SystemCallFilterId { get; }
    public bool AllowThreadOptOut { get; }
    public bool AllowRemoteDowngrade { get; }
    public bool AuditProhibitDynamicCode { get; }
    public bool NoChildProcessCreation { get; }

    public bool AuditNoChildProcessCreation { get; }
    public bool AllowSecureProcessCreation { get; }
    public bool EnableExportAddressFilter { get; }
    public bool AuditExportAddressFilter { get; }
    public bool EnableExportAddressFilterPlus { get; }
    public bool AuditExportAddressFilterPlus { get; }
    public bool EnableImportAddressFilter { get; }
    public bool AuditImportAddressFilter { get; }
    public bool EnableRopStackPivot { get; }
    public bool AuditRopStackPivot { get; }
    public bool EnableRopCallerCheck { get; }
    public bool AuditRopCallerCheck { get; }
    public bool EnableRopSimExec { get; }
    public bool AuditRopSimExec { get; }
    public bool SmtBranchTargetIsolation { get; }
    public bool IsolateSecurityDomain { get; }
    public bool DisablePageCombine { get; }
    public bool SpeculativeStoreBypassDisable { get; }
    public bool EnableUserShadowStack { get; }
    public bool AuditUserShadowStack { get; }
    public bool SetContextIpValidation { get; }
    public bool AuditSetContextIpValidation { get; }
    public bool EnableUserShadowStackStrictMode { get; }
    public bool BlockNonCetBinaries { get; }
    public bool BlockNonCetBinariesNonEhcont { get; }
    public bool AuditBlockNonCetBinaries { get; }
    public bool CetDynamicApisOutOfProcOnly { get; }
    public bool SetContextIpValidationRelaxedMode { get; }
    public bool EnforceRedirectionTrust { get; }
    public bool AuditRedirectionTrust { get; }
}
#pragma warning restore 1591

