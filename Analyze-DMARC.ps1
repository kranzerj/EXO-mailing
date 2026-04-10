param([string]$Path = ".")

# --- ZIP-Dateien entpacken ---
Get-ChildItem -Path $Path -Filter "*.zip" | ForEach-Object {
    Write-Host "Entpacke ZIP: $($_.Name)" -ForegroundColor Cyan
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($_.FullName, $Path)
        Remove-Item $_.FullName -Force
        Write-Host "  -> Entpackt und Archiv gelöscht" -ForegroundColor Green
    } catch {
        Write-Host "  -> FEHLER: $_" -ForegroundColor Red
    }
}

# --- GZ-Dateien entpacken ---
Get-ChildItem -Path $Path -Filter "*.gz" | ForEach-Object {
    Write-Host "Entpacke GZ: $($_.Name)" -ForegroundColor Cyan
    
    $gzFile = $_.FullName
    $xmlFile = $gzFile -replace '\.gz$', ''
    
    try {
        $stream = New-Object System.IO.FileStream($gzFile, [System.IO.FileMode]::Open)
        $gzip = New-Object System.IO.Compression.GzipStream($stream, [System.IO.Compression.CompressionMode]::Decompress)
        $output = [System.IO.File]::Create($xmlFile)
        $gzip.CopyTo($output)
        $output.Close()
        $gzip.Close()
        $stream.Close()
        
        Remove-Item $gzFile -Force
        Write-Host "  -> Entpackt und Archiv gelöscht" -ForegroundColor Green
    } catch {
        Write-Host "  -> FEHLER: $_" -ForegroundColor Red
    }
}

# --- Analyse der XML Files ---
$results = @{
    Total = 0
    PassPass = 0
    DKIMFail = 0
    SPFFail = 0
    BothFail = 0
}

$failures = @()

Get-ChildItem -Path $Path -Filter "*.xml" | ForEach-Object {
    [xml]$xml = Get-Content $_.FullName -Raw
    
    $reportOrg = $xml.feedback.report_metadata.org_name
    $dateBegin = [DateTimeOffset]::FromUnixTimeSeconds($xml.feedback.report_metadata.date_range.begin).DateTime
    $dateEnd = [DateTimeOffset]::FromUnixTimeSeconds($xml.feedback.report_metadata.date_range.end).DateTime
    
    $xml.feedback.record | ForEach-Object {
        $results.Total += $_.row.count
        $dkim = $_.row.policy_evaluated.dkim
        $spf = $_.row.policy_evaluated.spf
        
        if ($dkim -eq "pass" -and $spf -eq "pass") { 
            $results.PassPass += $_.row.count 
        } else {
            if ($dkim -ne "pass" -and $spf -ne "pass") { $results.BothFail += $_.row.count }
            elseif ($dkim -ne "pass") { $results.DKIMFail += $_.row.count }
            elseif ($spf -ne "pass") { $results.SPFFail += $_.row.count }
            
            $failures += [PSCustomObject]@{
                ReportOrg = $reportOrg
                DateBegin = $dateBegin
                DateEnd = $dateEnd
                SourceIP = $_.row.source_ip
                Count = $_.row.count
                DKIM = $dkim
                SPF = $spf
                Disposition = $_.row.policy_evaluated.disposition
                EnvelopeFrom = $_.identifiers.envelope_from
                HeaderFrom = $_.identifiers.header_from
                EnvelopeTo = $_.identifiers.envelope_to
                DKIMDomain = ($_.auth_results.dkim | Select-Object -First 1).domain
                DKIMResult = ($_.auth_results.dkim | Select-Object -First 1).result
                SPFDomain = $_.auth_results.spf.domain
                SPFResult = $_.auth_results.spf.result
            }
        }
    }
}

Write-Host "`nDMARC Report Summary:" -ForegroundColor Cyan
Write-Host "Total Messages: $($results.Total)" -ForegroundColor White
Write-Host "DKIM+SPF Pass: $($results.PassPass) ($([math]::Round($results.PassPass/$results.Total*100,1))%)" -ForegroundColor Green
Write-Host "Only SPF Fail: $($results.SPFFail) ($([math]::Round($results.SPFFail/$results.Total*100,1))%)" -ForegroundColor Yellow
Write-Host "Only DKIM Fail: $($results.DKIMFail) ($([math]::Round($results.DKIMFail/$results.Total*100,1))%)" -ForegroundColor Yellow
Write-Host "Both Fail: $($results.BothFail) ($([math]::Round($results.BothFail/$results.Total*100,1))%)" -ForegroundColor Red

if ($failures.Count -gt 0) {
    $csvPath = Join-Path $Path "DMARC-Failures.csv"
    $failures | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Write-Host "`nFailures exported to: $csvPath" -ForegroundColor Yellow
    Write-Host "Total failure records: $($failures.Count)" -ForegroundColor Yellow
}
