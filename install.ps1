param (
  [Parameter()]
  [switch]
  $UninstallSpotifyStoreEdition = (Read-Host -Prompt 'Uninstall Spotify Windows Store edition if it exists (Y/N)') -eq 'y',
  [Parameter()]
  [switch]
  $UpdateSpotify
)

$PSDefaultParameterValues['Stop-Process:ErrorAction'] = [System.Management.Automation.ActionPreference]::SilentlyContinue

[System.Version] $minimalSupportedSpotifyVersion = '1.2.8.923'

function Get-File
{
  param (
    [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [System.Uri]
    $Uri,
    [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [System.IO.FileInfo]
    $TargetFile,
    [Parameter(ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [Int32]
    $BufferSize = 1,
    [Parameter(ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('KB, MB')]
    [String]
    $BufferUnit = 'MB',
    [Parameter(ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('KB, MB')]
    [Int32]
    $Timeout = 10000
  )

  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  $useBitTransfer = $null -ne (Get-Module -Name BitsTransfer -ListAvailable) -and ($PSVersionTable.PSVersion.Major -le 5) -and ((Get-Service -Name BITS).StartType -ne [System.ServiceProcess.ServiceStartMode]::Disabled)

  if ($useBitTransfer)
  {
    Start-BitsTransfer -Source $Uri -Destination "$($TargetFile.FullName)"
  }
  else
  {
    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.set_Timeout($Timeout)
    $response = $request.GetResponse()
    $totalLength = [System.Math]::Floor($response.get_ContentLength() / 1024)
    $responseStream = $response.GetResponseStream()
    $targetStream = New-Object -TypeName ([System.IO.FileStream]) -ArgumentList "$($TargetFile.FullName)", Create
    switch ($BufferUnit)
    {
      'KB' { $BufferSize = $BufferSize * 1024 }
      'MB' { $BufferSize = $BufferSize * 1024 * 1024 }
      Default { $BufferSize = 1024 * 1024 }
    }
    $buffer = New-Object byte[] $BufferSize
    $count = $responseStream.Read($buffer, 0, $buffer.length)
    $downloadedBytes = $count
    $downloadedFileName = $Uri -split '/' | Select-Object -Last 1
    while ($count -gt 0)
    {
      $targetStream.Write($buffer, 0, $count)
      $count = $responseStream.Read($buffer, 0, $buffer.length)
      $downloadedBytes = $downloadedBytes + $count
    }

    $targetStream.Flush()
    $targetStream.Close()
    $targetStream.Dispose()
    $responseStream.Dispose()
  }
}

function Test-SpotifyVersion
{
  param (
    [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [System.Version]
    $MinimalSupportedVersion,
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [System.Version]
    $TestedVersion
  )

  process
  {
    return ($MinimalSupportedVersion.CompareTo($TestedVersion) -le 0)
  }
}

$spotifyDirectory = Join-Path -Path $env:APPDATA -ChildPath 'Spotify'
$spotifyExecutable = Join-Path -Path $spotifyDirectory -ChildPath 'Spotify.exe'
$spotifyApps = Join-Path -Path $spotifyDirectory -ChildPath 'Apps'

[System.Version] $actualSpotifyClientVersion = (Get-ChildItem -LiteralPath $spotifyExecutable -ErrorAction:SilentlyContinue).VersionInfo.ProductVersionRaw

Stop-Process -Name Spotify
Stop-Process -Name SpotifyWebHelper

if ($PSVersionTable.PSVersion.Major -ge 7)
{
  Import-Module Appx -UseWindowsPowerShell -WarningAction:SilentlyContinue
}

if (Get-AppxPackage -Name SpotifyAB.SpotifyMusic)
{
  if ($UninstallSpotifyStoreEdition)
  {
    Get-AppxPackage -Name SpotifyAB.SpotifyMusic | Remove-AppxPackage
  }
  else
  {
    Read-Host "Exiting...`nPress any key to exit..."
    exit
  }
}

Push-Location -LiteralPath $env:TEMP
try
{
  New-Item -Type Directory -Name "BlockTheSpot-$(Get-Date -UFormat '%Y-%m-%d_%H-%M-%S')" |
  Convert-Path |
  Set-Location
}
catch
{
  Read-Host 'Press any key to exit...'
  exit
}

$spotifyInstalled = Test-Path -LiteralPath $spotifyExecutable

if (-not $spotifyInstalled) {
  $unsupportedClientVersion = $true
} else {
  $unsupportedClientVersion = ($actualSpotifyClientVersion | Test-SpotifyVersion -MinimalSupportedVersion $minimalSupportedSpotifyVersion) -eq $false
}

if (-not $UpdateSpotify -and $unsupportedClientVersion)
{
  if ((Read-Host -Prompt 'In order to install Block the Spot, your Spotify client must be updated. Do you want to continue? (Y/N)') -ne 'y')
  {
    exit
  }
}

if (-not $spotifyInstalled -or $UpdateSpotify -or $unsupportedClientVersion)
{
  $spotifySetupFilePath = Join-Path -Path $PWD -ChildPath 'SpotifyFullSetup.exe'
  try
  {
    if ([Environment]::Is64BitOperatingSystem) {
      $uri = 'https://download.scdn.co/SpotifyFullSetupX64.exe'
    } else {
      $uri = 'https://download.scdn.co/SpotifyFullSetup.exe'
    }
    Get-File -Uri $uri -TargetFile "$spotifySetupFilePath"
  }
  catch
  {
    Read-Host 'Press any key to exit...'
    exit
  }
  New-Item -Path $spotifyDirectory -ItemType:Directory -Force | Write-Verbose

  [System.Security.Principal.WindowsPrincipal] $principal = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $isUserAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
  if ($isUserAdmin)
  {
    $apppath = 'powershell.exe'
    $taskname = 'Spotify install'
    $action = New-ScheduledTaskAction -Execute $apppath -Argument "-NoLogo -NoProfile -Command & `'$spotifySetupFilePath`'"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -WakeToRun
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskname -Settings $settings -Force | Write-Verbose
    Start-ScheduledTask -TaskName $taskname
    Start-Sleep -Seconds 2
    Unregister-ScheduledTask -TaskName $taskname -Confirm:$false
    Start-Sleep -Seconds 2
  }
  else
  {
    Start-Process -FilePath "$spotifySetupFilePath"
  }

  while ($null -eq (Get-Process -Name Spotify -ErrorAction SilentlyContinue))
  {
    Start-Sleep -Milliseconds 100
  }

  Stop-Process -Name Spotify
  Stop-Process -Name SpotifyWebHelper
  if ([Environment]::Is64BitOperatingSystem) {
    Stop-Process -Name SpotifyFullSetupX64
  } else {
     Stop-Process -Name SpotifyFullSetup
  }
}

$elfPath = Join-Path -Path $PWD -ChildPath 'chrome_elf.zip'
try
{
  $bytes = [System.IO.File]::ReadAllBytes($spotifyExecutable)
  $peHeader = [System.BitConverter]::ToUInt16($bytes[0x3C..0x3D], 0)
  $is64Bit = $bytes[$peHeader + 4] -eq 0x64

  if ($is64Bit) {
    $uri = 'https://github.com/FSOCIETY-WYLD/spotify/releases/latest/download/chrome_elf.zip'
  } else {
    $uri = 'https://github.com/FSOCIETY-WYLD/spotify/releases/download/spotifyyyy/chrome_elf.zip'
  }

  Get-File -Uri $uri -TargetFile "$elfPath"
}
catch
{
  Start-Sleep
}

Expand-Archive -Force -LiteralPath "$elfPath" -DestinationPath $PWD
Remove-Item -LiteralPath "$elfPath" -Force

$patchFiles = (Join-Path -Path $PWD -ChildPath 'dpapi.dll'), (Join-Path -Path $PWD -ChildPath 'config.ini')

Copy-Item -LiteralPath $patchFiles -Destination "$spotifyDirectory"

function Install-VcRedist {
    $vcRedistX86Url = "https://aka.ms/vs/17/release/vc_redist.x86.exe"
    $vcRedistX64Url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"

    if ([Environment]::Is64BitOperatingSystem) {
        if (!(Test-Path 'HKLM:\Software\Microsoft\VisualStudio\14.0\VC\Runtimes\x64')) {
            $vcRedistX64File = Join-Path -Path $PWD -ChildPath 'vc_redist.x64.exe'
            Get-File -Uri $vcRedistX64Url -TargetFile $vcRedistX64File
            Start-Process -FilePath $vcRedistX64File -ArgumentList "/install /quiet /norestart" -Wait
        }
    }
    else {
        if (!(Test-Path 'HKLM:\Software\Microsoft\VisualStudio\14.0\VC\Runtimes\x86')) {
            $vcRedistX86File = Join-Path -Path $PWD -ChildPath 'vc_redist.x86.exe'
            Get-File -Uri $vcRedistX86Url -TargetFile $vcRedistX86File
            Start-Process -FilePath $vcRedistX86File -ArgumentList "/install /quiet /norestart" -Wait
        }
    }
}

Install-VcRedist

$tempDirectory = $PWD
Pop-Location

Remove-Item -LiteralPath $tempDirectory -Recurse

Start-Process -WorkingDirectory $spotifyDirectory -FilePath $spotifyExecutable
