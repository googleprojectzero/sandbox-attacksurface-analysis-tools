using NtCoreLib;
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="description">Specify check mode.</para>
/// </summary>
public enum WindowStationCheckMode
{
    /// <summary>
    /// Only check Window Stations.
    /// </summary>
    WindowStationOnly,
    /// <summary>
    /// Only check Desktops.
    /// </summary>
    DesktopOnly,
    /// <summary>
    /// Check Window Stations and Desktops.
    /// </summary>
    WindowStationAndDesktop
}

/// <summary>
/// <para type="synopsis">Get a list of Window Station an/or Desktops accessible by a specified token.</para>
/// <para type="description">This cmdlet checks all Window Stations/Desktops and tries to determine
/// if one or more specified tokens can access them. If no tokens are specified then the 
/// current process token is used. Note, this will only check the current session.</para>
/// </summary>
/// <example>
///   <code>Get-AccessibleWindowStation</code>
///   <para>Check all accessible Window Stations for the current process token.</para>
/// </example>
/// <example>
///   <code>Get-AccessibleWindowStation -CheckMode WindowStationAndDesktop</code>
///   <para>Check all accessible Window Stations and Desktops for the current process token.</para>
/// </example>
/// <example>
///   <code>Get-AccessibleWindowStation -ProcessIds 1234,5678</code>
///   <para>>Check all accessible Window Stations for the process tokens of PIDs 1234 and 5678</para>
/// </example>
/// <example>
///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleWindowStation -Tokens $token</code>
///   <para>Get all Window Stations which can be accessed by a low integrity copy of current token.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "AccessibleWindowStation")]
[OutputType(typeof(CommonAccessCheckResult))]
public class GetAccessibleWindowStation : CommonAccessBaseWithAccessCmdlet<WindowStationAccessRights>
{
    /// <summary>
    /// <para type="description">Specify check mode.</para>
    /// </summary>
    [Parameter]
    public WindowStationCheckMode CheckMode { get; set; }

    /// <summary>
    /// <para type="description">Specify desktop access rights when checking Desktops.</para>
    /// </summary>
    [Parameter]
    [Alias("DesktopAccessRights")]
    public DesktopAccessRights DesktopAccess { get; set; }

    private void RunAccessCheckDesktop(IEnumerable<TokenEntry> tokens, NtWindowStation winsta)
    {
        NtType desktop_type = NtType.GetTypeByType<NtDesktop>();
        AccessMask desktop_access_rights = desktop_type.GenericMapping.MapMask(DesktopAccess);
        using var desktops = winsta.GetAccessibleDesktops().ToDisposableList();
        foreach (var desktop in desktops)
        {
            if (desktop.IsAccessGranted(DesktopAccessRights.ReadControl))
            {
                var sd = desktop.SecurityDescriptor;
                foreach (TokenEntry token in tokens)
                {
                    AccessMask granted_access = NtSecurity.GetMaximumAccess(sd,
                        token.Token, desktop_type.GenericMapping);
                    if (IsAccessGranted(granted_access, desktop_access_rights))
                    {
                        WriteAccessCheckResult($"{winsta.FullPath}{desktop.FullPath}", desktop_type.Name, granted_access, desktop_type.GenericMapping,
                            sd, desktop_type.AccessRightsType, true, token.Information);
                    }
                }
            }
        }
    }

    private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
    {
        NtType winsta_type = NtType.GetTypeByType<NtWindowStation>();
        
        AccessMask winsta_access_rights = winsta_type.GenericMapping.MapMask(Access);
        bool check_winsta = CheckMode == WindowStationCheckMode.WindowStationOnly || CheckMode == WindowStationCheckMode.WindowStationAndDesktop;
        bool check_desktop = CheckMode == WindowStationCheckMode.DesktopOnly || CheckMode == WindowStationCheckMode.WindowStationAndDesktop;

        using var winstas = NtWindowStation.GetAccessibleWindowStations().ToDisposableList();
        foreach (var winsta in winstas)
        {
            if (check_winsta && winsta.IsAccessGranted(WindowStationAccessRights.ReadControl))
            {
                var sd = winsta.SecurityDescriptor;
                foreach (TokenEntry token in tokens)
                {
                    AccessMask granted_access = NtSecurity.GetMaximumAccess(sd,
                        token.Token, winsta_type.GenericMapping);
                    if (IsAccessGranted(granted_access, winsta_access_rights))
                    {
                        WriteAccessCheckResult(winsta.FullPath, winsta_type.Name, granted_access, winsta_type.GenericMapping,
                            sd, winsta_type.AccessRightsType, true, token.Information);
                    }
                }
            }

            if (check_desktop && winsta.IsAccessGranted(WindowStationAccessRights.EnumDesktops))
            {
                RunAccessCheckDesktop(tokens, winsta);
            }
        }
    }
}
