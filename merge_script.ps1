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

function Get-MergedScript {
    param([string]$Path)
    
    try {
        $Path = Resolve-Path $Path

        $c = Get-Content -Path "$Path\NtObjectManager.psm1" | Out-String
        $i = $c.IndexOf("# Source the external scripts into this module.")

        $res = $c.Substring(0, $i)
        $fs = ls "$Path\*.ps1"
        foreach($f in $fs) {
            $c = Get-Content -Path $f.FullName
            $c = Remove-LeadingComment $c | Out-String
            $res += $c
        }
        $res
    } catch {
        Write-Error $_
    }
}