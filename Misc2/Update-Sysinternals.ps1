$LogFile = Join-Path $env:ProgramData "Update-Sysinternals2025pf.log"


$DebugPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

function Write-Log 
{
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO",

        [switch]$NoConsole
    )

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry  = "$timestamp [$Level] $Message"

    # Write to log file
    if ($Level -ne "DEBUG")
    {
        Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
     
    # Also write to console (unless disabled)
    if (-not $NoConsole) 
    {
        switch ($Level) 
        {
            "INFO"  { Write-Host $logEntry -ForegroundColor Green }
            "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
            "ERROR" { Write-Host $logEntry -ForegroundColor Red }
            "DEBUG" { Write-Host $logEntry -ForegroundColor Cyan }
        }
    }
}

function Get-SignatureIssueToken
{
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    $sig = Get-AuthenticodeSignature -LiteralPath $Path

    switch ([string]$sig.Status)
    {
        'Valid'
        {
            # a real Sysinternals binary is Authenticode-signed by Microsoft Corporation
            if ($sig.SignerCertificate -and ($sig.SignerCertificate.Subject -match 'O=Microsoft Corporation'))
            {
                return $null   # trusted - nothing to flag
            }
            return 'notmicrosoft'
        }
        'NotSigned'    { return 'nosignature' }
        'HashMismatch' { return 'tampered' }
        default        { return ([string]$sig.Status).ToLowerInvariant() }
    }
}

Write-Log "Starting..." -Level INFO

$SysInternalsBaseUrl = "https://live.sysinternals.com"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin)
{
    $baseFolder = "C:\Program Files\SysInternals\"
}
else 
{
    $baseFolder = "C:\SysInternals\"
}

$subFolders = @('', 'files', 'tools')
# if you really care: $subFolders += 'ARM64'

# only these file types can carry an Authenticode signature worth checking
$signableExtensions = @('.exe', '.dll', '.sys', '.ocx', '.cpl', '.scr', '.efi', '.msi', '.msix', '.appx', '.cab', '.cat', '.ps1', '.psm1', '.vbs', '.js', '.wsf')

New-Item -ItemType Directory -Path $baseFolder -Force | Out-Null
if (!(Test-Path $baseFolder))
{
    Write-Log ($baseFolder + ' does not exist and cannot create it! Exiting...') -Level ERROR
    exit 1
}

$baseFolder = (Get-Item $baseFolder).FullName

if (!($SysInternalsBaseUrl.EndsWith('/')))
{
    $SysInternalsBaseUrl += '/'
}

foreach ($subFolder in $subFolders)
{
    $todayFolderFullName = $null
    $currentWorkFolder = Join-Path $baseFolder $subFolder
    New-Item -ItemType Directory -Path $currentWorkFolder -Force | Out-Null
    if (!(Test-Path $currentWorkFolder))
    {
        Write-Log ($currentWorkFolder + ' does not exist and cannot create it! Trying to continue anyway...') -Level WARN
        continue
    }

    try
    {
        $pageResponse = Invoke-WebRequest -Uri ($SysInternalsBaseUrl + $subFolder) -UseBasicParsing # '/' presence at the end of baseurl ensured above
    }
    catch
    {
        Write-Log ('Listing ' + ($SysInternalsBaseUrl + $subFolder) + ' failed: ' + $_.Exception.Message + ' - skipping folder.') -Level ERROR
        continue
    }
    $baseUri = [System.Uri]$SysInternalsBaseUrl
    $links = $pageResponse.Links | Select-Object -ExpandProperty href

    foreach ($link in $links)
    {
        $backupFullFileName = $null
        Write-Log $link -Level DEBUG
        if ($link.EndsWith('/')) # dir, skip
        {
            continue
        }

        $itemUri = [System.Uri]::new($baseUri,$link)
        $fileName = [System.IO.Path]::GetFileName($itemUri.AbsoluteUri)
        $fullFileName = Join-Path $currentWorkFolder $fileName

        try
        {
            $response = Invoke-WebRequest -Uri $itemUri.AbsoluteUri -UseBasicParsing -Method Head #headers only
        }
        catch
        {
            Write-Log ('Requesting headers for ' + $itemUri.AbsoluteUri + ' failed: ' + $_.Exception.Message) -Level ERROR
            continue
        }
        if ($response.StatusCode -ne 200)
        {
            Write-Log ('Requesting headers for ' + $itemUri.AbsoluteUri + ' returned ' + $response.StatusCode.ToString()) -Level ERROR
            continue
        }

        # initial values to be replaced where possible
        $diskSize = -1
        $diskLastModified = [datetime](0)
        $webSize = 0
        $webLastModified = (Get-Date).ToUniversalTime()

        if (Test-Path $fullFileName)
        {
            $diskSize = (Get-ChildItem -Path $fullFileName).Length
            $diskLastModified = (Get-ChildItem $fullFileName).LastWriteTimeUtc
        }

        $lengthStr = $response.Headers["Content-Length"]
        if ($lengthStr)
        {
            $webSize = [long]::Parse($lengthStr)
        }

        $lastModifiedStr = $response.Headers["Last-Modified"]
        if ($lastModifiedStr)
        {
            # Last-Modified is GMT/UTC; parse to a UTC DateTime so it compares cleanly with LastWriteTimeUtc
            $webLastModified = [DateTime]::Parse($lastModifiedStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
        }


        # Change-detection gate.
        # Size is the primary content-identity signal here (mirrors are content-synced but their
        # Last-Modified timestamps are NOT in sync, so exact time comparison would churn downloads).
        # Safety net: if the size matches but the timestamps differ by more than 24h - beyond the
        # expected inter-mirror skew - treat it as a possible real update and fall through to
        # download + hash-compare (which rolls back if the content turns out identical).
        $timeDeltaHours = [math]::Abs(($webLastModified - $diskLastModified).TotalHours)
        if (($webSize -eq $diskSize) -and ($timeDeltaHours -le 24))
        {
            # same size, timestamps close enough - we have the file already
            continue
        }

        # we've got something new!
        Write-Log ($fullFileName + ' : ' + $diskLastModified + ' --> ' + $webLastModified) -Level DEBUG

        if (Test-Path $fullFileName)
        {
            # do backup
            $todayStr = (Get-Date).ToString('yyyy-MM-dd')
            $todayFolderFullName = Join-Path $currentWorkFolder $todayStr

            New-Item -ItemType Directory -Path $todayFolderFullName -Force | Out-Null

            # and what if we have the backup today already...?
            $backupFullFileName = Join-Path $todayFolderFullName ([System.IO.Path]::GetFileName($fullFileName))
            if (Test-Path $backupFullFileName)
            {
                Write-Log "New backup." -Level DEBUG
                Rename-Item -Path $backupFullFileName `
                    -NewName ([System.IO.Path]::GetFileNameWithoutExtension($fullFileName) + '.' + (Get-Date).Ticks.ToString() + [System.IO.Path]::GetExtension($fullFileName))
            }
            Move-Item -Path $fullFileName -Destination $todayFolderFullName
        }


        # download. No file on disk at this point (didn't exist or was moved)
        try 
        {
            Invoke-WebRequest -Uri $itemUri.AbsoluteUri -OutFile $fullFileName -UseBasicParsing
        }
        catch 
        {
                Write-Log ("Download failed for " + $itemUri.AbsoluteUri + " ---> " + $fullFileName) -Level WARN
                # restore the backup we just moved aside, so we don't end up with nothing in place
                if ((-not (Test-Path -Path $fullFileName)) -and $backupFullFileName -and (Test-Path -Path $backupFullFileName))
                {
                    Write-Log "Restoring backup after failed download." -Level WARN
                    Move-Item -Path $backupFullFileName -Destination $fullFileName
                }
                continue
        }

        # rollback if same hash
        if ($backupFullFileName -and (Test-Path -Path $backupFullFileName) -and (Test-Path -Path $fullFileName))
        {
            if ((Get-FileHash $fullFileName).Hash -eq (Get-FileHash $backupFullFileName).Hash)
            {
                Write-Log "Same hash, cleaning up." -Level DEBUG
                Remove-Item -Path $fullFileName
                Move-Item -Path $backupFullFileName -Destination $fullFileName
            }
            else
            {
                Write-Log "Really new!" -Level INFO
            }
        }

        # verify Authenticode signature (only for file types that can carry one);
        # if it isn't a valid Microsoft/Sysinternals signature, flag what's wrong in the file name
        $finalFileName = $fullFileName
        if ((Test-Path $fullFileName) -and ($signableExtensions -contains ([System.IO.Path]::GetExtension($fullFileName)).ToLowerInvariant()))
        {
            $sigIssue = Get-SignatureIssueToken -Path $fullFileName
            if ($sigIssue)
            {
                $ext = [System.IO.Path]::GetExtension($fullFileName)
                $flaggedName = [System.IO.Path]::GetFileNameWithoutExtension($fullFileName) + '.' + $sigIssue + $ext
                $finalFileName = Join-Path $currentWorkFolder $flaggedName
                Write-Log ('Signature check failed (' + $sigIssue + ') for ' + $fileName + ' --> keeping as ' + $flaggedName) -Level WARN
                Move-Item -Path $fullFileName -Destination $finalFileName -Force
            }
        }

        #set modified time
        if (Test-Path $finalFileName)
        {
            (Get-Item $finalFileName).LastWriteTimeUtc = $webLastModified
        }
    }

    # do we have and need todayFolderFullName? It was created due to diffs, but may be empty if all hashes matched
    if ($todayFolderFullName -and (Test-Path -Path $todayFolderFullName))
    {
        if (!(Get-ChildItem $todayFolderFullName))
        {
            Write-Log "Removing empty backup folder." -Level DEBUG            
            Remove-Item -Path $todayFolderFullName
        }
    }

}

Write-Log "Done." -Level INFO
