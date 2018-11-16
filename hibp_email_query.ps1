# Have I Been Pwned Email Query
# Version 0.7

function get_dir {
    $invoke = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $invoke.MyCommand.Path
}

$script_path = get_dir
$inputFile = $script_path + "\users.txt"

$breachAddresses = [ordered]@{}
$pasteAddresses = [ordered]@{}

$cnt = 0
$cntAddresses = (Get-Content $inputFile | Measure-Object -Line).Lines
$start = Get-Date
$stop = Get-Date

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

    $estimatedTime = ($cntAddresses * 3) - 3

    Write-Host "Email Addresses: " -NoNewLine
    Write-Host $Script:cntAddresses -ForegroundColor Yellow
    Write-Host "Estimated Time:  $estimatedTime`n"
    Write-Host "`nInfo: Press Ctrl-C to interrupt querying`n`n"
    Write-Host "Querying...`n--------------------------------`n"

    ForEach ($k in (Get-Content $inputFile)) {
        $Local:breachUrl = "https://haveibeenpwned.com/api/v2/breachedaccount/" + $k + "?truncateResponse=true"
        $Local:pasteUrl = "https://haveibeenpwned.com/api/v2/pasteaccount/" + $k
        $breach_http_status = $null
        $paste_http_status = $null
        $Script:cnt += 1
        
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

        Write-Host "$Script:cnt/$cntAddresses :: $k" -ForegroundColor Cyan

        If ($breach_http_status -like "*(404) Not Found*") {
            Write-Host "Breach: " -NoNewLine; Write-Host "Clean" -ForegroundColor Green
            $Script:breachAddresses."$k" = [ordered]@{"address"=$k; "pwned?"="n"}
        } Else {
            Write-Host "Breach: " -NoNewline
            $Script:breachAddresses."$k" = [ordered]@{"address"=$k; "pwned?"="y"}
            $Script:breachQuery.Name | ForEach {
                Write-Host ("{0}, " -f $_) -ForegroundColor Red -NoNewline
                $Script:breachAddresses."$k".add("$_","y")
            }
            Write-Host
        }

        If ($paste_http_status -like "*(404) Not Found*") {
            Write-Host "Paste:  " -NoNewLine; Write-Host "Clean" -ForegroundColor Green
            $Script:pasteAddresses."$k" = [ordered]@{"address"=$k; "pwned?"="n"}
        } Else {
            Write-Host "Paste:  " -NoNewLine
            $Script:pasteAddresses."$k" = [ordered]@{"address"=$k; "pwned?"="y"}
            $pasteQuery | ForEach {
                If ($_.Title -eq $null) {
                    Write-Host ("{0}: Untitled ({1}), " -f $_.Source,$_.Id) -ForegroundColor Red -NoNewline
                    $name = $_.Source + " (" + $_.Id + ")"
                    $Script:pasteAddresses."$k".add($name,"y")
                } Else {
                    Write-Host ("{0}: {1}, " -f $_.Source,$_.Title) -ForegroundColor Red -NoNewLine
                    $name = $_.Source + ": " + $_.Title
                    If ($name -in $Script:pasteAddresses.$k.Keys) {
                        $altName =$_.Source + " (" + $_.Title + "[" + $_.EmailCount +"]" + ")"
                        $Script:pasteAddresses."$k".add($altName,"y")
                    } Else {
                        $Script:pasteAddresses."$k".add($name,"y")
                    }
                }
            }
            Write-Host
        }
        
        Write-Host
        If ($Script:cnt -lt $Script:cntAddresses) {
            Start-Sleep -Seconds 2
        }
    }

    Write-Host "`================================`n"
    $Script:stop = Get-Date
}

function show_results {
    Write-Host "`n--- Results ---"
    $posBreach = 0
    $cleanBreach = 0
    $posPaste = 0
    $cleanPaste = 0

    $Script:breachAddresses.Keys | ForEach {
        If ($Script:breachAddresses.$_."pwned?" -eq "y") {
            $posBreach += 1
        } Else {
            $cleanBreach += 1
        }
    }

    $Script:pasteAddresses.Keys | ForEach {
        If ($Script:pasteAddresses.$_."pwned?" -eq "y") {
            $posPaste += 1
        } Else {
            $cleanPaste += 1
        }
    }

    Write-Host "`nQueries: " $Script:cntAddresses
    Write-Host "Breaches: " -NoNewline; Write-Host $posBreach -ForegroundColor Red -NoNewline; Write-host "`t`tClean: " -NoNewLine; Write-Host $cleanBreach -ForegroundColor Green
    Write-Host "Pastes:   " -NoNewline; Write-Host $posPaste -ForegroundColor Red -NoNewline; Write-Host "`t`tClean: " -NoNewLine; Write-Host $cleanPaste -ForegroundColor Green
    Write-Host
}

function build_CSV($inputHashTable, $type) {
    $Local:ErrorActionPreference = 'SilentlyContinue'
    $tempHeader = New-Object System.Collections.Generic.List[System.Object]
    $csvHeader = [ordered]@{}
    
    # Breach file
    ForEach ($email in $Script:breachAddresses.Keys) {
        ForEach ($url in $Script:breachAddresses.$email.keys) {
            $tempHeader.Add($url)
        }
    }
    
    $tempHeader = $tempHeader | Select-Object -Unique | Sort-Object

    $tempHeader | ForEach {
        $csvHeader.Add($_,$null)
    }

    $csvHeader.Remove("address"); $csvHeader.Remove("pwned?")
    $csvHeader = $csvHeader | sort
    $csvHeader.Insert(0,"address",$null); $csvHeader.Insert(1,"pwned?",$null)

    New-Object -TypeName psobject -Property $csvHeader | Export-Csv -Path "$Script:script_path\$date`_$time`_hibp_breach_results.csv" -NoTypeInformation -Append -Force

    # Paste file
    $tempHeader = New-Object System.Collections.Generic.List[System.Object]
    $csvHeader = [ordered]@{}

    ForEach ($email in $Script:pasteAddresses.Keys) {
        ForEach ($url in $Script:pasteAddresses.$email.keys) {
            $tempHeader.Add($url)
        }
    }
    
    $tempHeader = $tempHeader | Select-Object -Unique | Sort-Object

    $tempHeader | ForEach {
        $csvHeader.Add($_,$null)
    }

    $csvHeader.Remove("address"); $csvHeader.Remove("pwned?")
    $csvHeader = $csvHeader | sort
    $csvHeader.Insert(0,"address",$null); $csvHeader.Insert(1,"pwned?",$null)

    New-Object -TypeName psobject -Property $csvHeader | Export-Csv -Path "$Script:script_path\$date`_$time`_hibp_paste_results.csv" -NoTypeInformation -Append -Force

    $ErrorActionPreference = 'Continue'
}

function save_CSV {
    $date = Get-Date -UFormat %Y.%m.%d
    $time = Get-Date -UFormat %H.%M.%S
    $elapsed = $Script:stop - $Script:start

    Write-Host "`n`n--- Exporting Results ---"
    Write-Host "`nSaving Breach results to " -NoNewLine; Write-Host "$date`_$time`_hibp_breach_results.csv" -ForegroundColor Yellow
    Write-Host "`Saving Paste results to  " -NoNewLine; Write-Host "$date`_$time`_hibp_paste_results.csv" -ForegroundColor Yellow
    Write-Host "Directory: $Script:script_path"

    build_CSV

    ForEach ($i in $Script:breachAddresses.Keys) {
        New-Object -TypeName psobject -Property $Script:breachAddresses.$i | Export-Csv -Path "$Script:script_path\$date`_$time`_hibp_breach_results.csv" -NoTypeInformation -Append -Force
    }

    ForEach ($i in $Script:pasteAddresses.Keys) {
        New-Object -TypeName psobject -Property $Script:pasteAddresses.$i | Export-Csv -Path "$Script:script_path\$date`_$time`_hibp_paste_results.csv" -NoTypeInformation -Append -Force
    }

    Write-Host "`n`n--------------------------------"
    Write-Host "`nStart: $Script:start `t Stop: $Script:stop `nElapsed: $elapsed"
}

welcome
Try {}
Catch {}
Finally {
    email_query
    show_results
    save_CSV
    pause
}