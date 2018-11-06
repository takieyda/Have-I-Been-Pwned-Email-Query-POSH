# Have I Been Pwned Email Query
# Version 0.5

function get_dir {
    $invoke = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $invoke.MyCommand.Path
}

$script_path = get_dir
$inputFile = $script_path + "\users.txt"

function pause {
    Read-Host "`nPress Enter to continue." | Out-Null
}


function welcome {
    Write-Host "`n`n================================`n|      Have I Been Pwned       |`n|         Email Query          |`n================================`n"
    Write-Host "Info: Due to restrictions for public API use, `nInfo: there is a 3 second pause between queries.`n"
    Write-Host "================================`n"
}

function email_query {
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    $cnt = (Get-Content $inputFile | Measure-Object -Line).Lines
    $estimatedTime = $cnt * 3

    Write-Host "Email Addresses: " -NoNewLine
    Write-Host $cnt -ForegroundColor Yellow
    Write-Host "Estimated Time: $estimatedTime`n"
    Write-Host "Info: Press Ctrl-C to interrupt querying`n"
    Write-Host "Querying...`n--------------------------------`n"

    Get-Content $inputFile | ForEach-Object {
        $Local:breachUrl = "https://haveibeenpwned.com/api/v2/breachedaccount/" + $_ + "?truncateResponse=true"
        $Local:pasteUrl = "https://haveibeenpwned.com/api/v2/pasteaccount/" + $_
        $breach_http_status = $null
        $paste_http_status = $null
        
        Try {
            $Script:breachQuery = Invoke-RestMethod -Uri $breachUrl
        } Catch [System.Net.WebException] {
            $breach_http_status = $_ | Out-String
        }

        Try {
            $Script:pasteQuery = Invoke-RestMethod -Uri $pasteUrl
        } Catch [System.Net.WebException] {
            $paste_http_status = $_ | Out-String
        }

        Write-Host "$_" -ForegroundColor Cyan

        If ($breach_http_status -like "*(404) Not Found*") {
            Write-Host "Breach: " -NoNewLine; Write-Host "Clean" -ForegroundColor Green
        } Else {
            Write-Host "Breach: " -NoNewline
            $breachQuery | ForEach {
                Write-Host ("{0}, " -f $_.Name) -ForegroundColor Red -NoNewline
            }
            Write-Host
        }

        If ($paste_http_status -like "*(404) Not Found*") {
            Write-Host "Paste:  " -NoNewLine; Write-Host "Clean" -ForegroundColor Green
        } Else {
            Write-Host "Paste:  " -NoNewLine
            $pasteQuery | ForEach {
                If ($_.Title -eq $null) {
                    Write-Host ("{0}: Untitled ({1}), " -f $_.Source,$_.Id) -ForegroundColor Red -NoNewline
                } Else {
                    Write-Host ("{0}: {1}, " -f $_.Source,$_.Title) -ForegroundColor Red -NoNewLine
                }
            }
            Write-Host
        }
        
        Write-Host
        Start-Sleep -Seconds 3
    }

    Write-Host "`================================`n"
}

welcome
Try {}
Catch {}
Finally {
    email_query
    pause
}