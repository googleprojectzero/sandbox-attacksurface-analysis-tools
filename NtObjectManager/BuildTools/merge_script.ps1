param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$Path,
    [switch]$RemoveSource
)

Set-StrictMode -Version Latest

function Remove-LeadingComment {
    param([string[]]$lines)

    $index = 0
    while($index -lt $lines.Count) {
        if (!$lines[$index].StartsWith("#")) {
            break
        }
        $index++
    }
    if ($index -lt $lines.Count) {
        $lines[$index..($lines.Count-1)]
    }
}
   
try {
    $Path = Resolve-Path $Path -ErrorAction Stop
    $mod_path = "$Path\NtObjectManager.psm1"
    $mod = Get-Content -Path $mod_path -ErrorAction Stop
    $found_start = $false
    $res = @()
    foreach($l in $mod) {
        if ($found_start -and $l.StartsWith('. "$PSScriptRoot\')) {
            $spath = $l.Replace('. "$PSScriptRoot', $Path).TrimEnd('"')
            $c = Get-Content -Path $spath -ErrorAction Stop
            $c = Remove-LeadingComment $c
            $res += $c
            if ($RemoveSource) {
                Remove-Item $spath
            }
        } elseif ($l -eq "# Source the external scripts into this module.") {
            $found_start = $true
        } else {
            $res += $l
        }
    }
    $res | Set-Content -Path $mod_path
} catch {
    Write-Error $_
    Exit 1
}
