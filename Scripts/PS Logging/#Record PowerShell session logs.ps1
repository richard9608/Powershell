#Record PowerShell session logs

function Record-SessionLogsLR {
    param([string]$ScriptName)

    $logFile = "C:\Users\LRichardson2_adm\Documents\PS Session Logs\$ScriptName-$(Get-Date -Format 'yyyy-MM-dd_HHmmss').txt"
    try {
        Start-Transcript -Path $logFile -ErrorAction Stop
        return $true
    } catch {
        Write-Host "Transcript already running. Skipping." -ForegroundColor Yellow
        return $false
    }
}

function Stop-SafeTranscript {
    param([bool]$ShouldStop)
    if ($ShouldStop) {
        Stop-Transcript
    }
}
