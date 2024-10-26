using namespace System.IO

function Get-attribute {
  # .SYNOPSIS
  #   Get file attribute
  # .Example
  #   Get-attribute -Path C:\demo\*.txt
  # .LINK
  #   https://ss64.com/ps/syntax-attrib.html
  [CmdletBinding()]
  [OutputType([string])]
  param([string]$Path)

  $ARCHIVE_ATTRIB = [FileAttributes]::Archive
  $READONLY_ATTRIB = [FileAttributes]::ReadOnly
  $HIDDEN_ATTRIB = [FileAttributes]::Hidden
  $SYSTEM_ATTRIB = [FileAttributes]::System

  $Files = Get-Item -Path $Path -Force

  if ($Files.Count -gt 1) {
    $Files = Get-ChildItem -Path $Path -Recurse -Force
  }

  foreach ($File in $Files) {
    $Attributes = ""

    if (((Get-ItemProperty -Path $File.FullName).Attributes -band $ARCHIVE_ATTRIB) -eq $ARCHIVE_ATTRIB) {
      $Attributes = "| Archive"
    }

    if (((Get-ItemProperty -Path $File.FullName).Attributes -band $READONLY_ATTRIB) -eq 1) {
      $Attributes = "$Attributes | Read-only"
    }

    if (((Get-ItemProperty -Path $File.FullName).Attributes -band $HIDDEN_ATTRIB) -eq 2) {
      $Attributes = "$Attributes | Hidden"
    }

    if (((Get-ItemProperty -Path $File.FullName).Attributes -band $SYSTEM_ATTRIB) -eq 4) {
      $Attributes = "$Attributes | System"
    }

    if ($Attributes -eq "") {
      $Attributes = "| Normal"
    }

    return "$File $Attributes"
  }
}


function Remove-attribute {
  # .SYNOPSIS
  # Remove file attribute

  # .Parameter Path

  # .Parameter Archive
  # Remove the Archive attribute

  # .Parameter ReadOnly
  # Remove the ReadOnly attribute

  # .Parameter Hidden
  # Remove the Hidden attribute

  # .Parameter System
  # Remove the Hidden attribute

  # .Example
  # Remove-attribute -Path "C:\logs\monday.csv" -Archive -ReadOnly -Hidden

  # .LINK
  # https://ss64.com/ps/syntax-attrib.html
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [string]$Path,

    [switch]$Archive = $false,

    [switch]$ReadOnly = $false,

    [switch]$Hidden = $false,

    [switch]$System = $false
  )

  $ARCHIVE_ATTRIB = [FileAttributes]::Archive
  $READONLY_ATTRIB = [FileAttributes]::ReadOnly
  $HIDDEN_ATTRIB = [FileAttributes]::Hidden

  $Files = Get-Item -Path $Path -Force

  if ($Files.Count -gt 1) {
    $Files = Get-ChildItem -Path $Path -Recurse -Force
  }

  foreach ($File in $Files) {
    if ($Archive.IsPresent -and ((Get-ItemProperty -Path $File.FullName).Attributes -band $ARCHIVE_ATTRIB)) {
      Set-ItemProperty -Path $File.Fullname -Name Attributes -Value ((Get-ItemProperty $File.FullName).Attributes -bxor $ARCHIVE_ATTRIB)
    }

    if ($ReadOnly.IsPresent -and ((Get-ItemProperty -Path $File.FullName).Attributes -band $READONLY_ATTRIB)) {
      Set-ItemProperty -Path $File.Fullname -Name Attributes -Value ((Get-ItemProperty $File.FullName).Attributes -bxor $READONLY_ATTRIB)
    }

    if ($Hidden.IsPresent -and ((Get-ItemProperty -Path $File.FullName).Attributes -band $HIDDEN_ATTRIB)) {
      Set-ItemProperty -Path $File.Fullname -Name Attributes -Value ((Get-ItemProperty $File.FullName).Attributes -bxor $HIDDEN_ATTRIB)
    }
  }
}

function Set-attribute {
  # .SYNOPSIS
  # Set file attribute

  # .Parameter Path

  # .Parameter Archive
  # Set the Archive attribute

  # .Parameter ReadOnly
  # Set the ReadOnly attribute

  # .Parameter Hidden
  # Set the Hidden attribute

  # .Example
  # .Set-attribute -Path "C:\logs\monday.csv" -ReadOnly -Hidden

  # .LINK
  # https://ss64.com/ps/syntax-attrib.html
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [string]$Path,

    [switch]$Archive = $false,

    [switch]$ReadOnly = $false,

    [switch]$Hidden = $false
  )

  $ARCHIVE_ATTRIB = [FileAttributes]::Archive
  $READONLY_ATTRIB = [FileAttributes]::ReadOnly
  $HIDDEN_ATTRIB = [FileAttributes]::Hidden

  $Files = Get-Item -Path $Path -Force

  if ($Files.Count -gt 1) {
    $Files = Get-ChildItem -Path $Path -Recurse -Force
  }

  foreach ($File in $Files) {
    if ($Archive.IsPresent) {
      Set-ItemProperty -Path $File.Fullname -Name Attributes -Value ((Get-ItemProperty $File.FullName).Attributes -bor $ARCHIVE_ATTRIB)
    }

    if ($ReadOnly.IsPresent) {
      Set-ItemProperty -Path $File.Fullname -Name Attributes -Value ((Get-ItemProperty $File.FullName).Attributes -bor $READONLY_ATTRIB)
    }

    if ($Hidden.IsPresent) {
      Set-ItemProperty -Path $File.Fullname -Name Attributes -Value ((Get-ItemProperty $File.FullName).Attributes -bor $HIDDEN_ATTRIB)
    }
  }
}

function Show-FileAttribute {
  <#
    .SYNOPSIS
        Shows the available file attributes
    .DESCRIPTION
        Shows the available file attributes
    .EXAMPLE
        Show-FileAttribute

        Would return
        ReadOnly
        Hidden
        System
        Directory
        Archive
        Device
        Normal
        Temporary
        SparseFile
        ReparsePoint
        Compressed
        Offline
        NotContentIndexed
        Encrypted
        IntegrityStream
        NoScrubData
    .EXAMPLE
        Show-FileAttribute

        Would return
        Name                 Dec Hex
        ----                 --- ---
        ReadOnly               1 0x1
        Hidden                 2 0x2
        System                 4 0x4
        Directory             16 0x10
        Archive               32 0x20
        Device                64 0x40
        Normal               128 0x80
        Temporary            256 0x100
        SparseFile           512 0x200
        ReparsePoint        1024 0x400
        Compressed          2048 0x800
        Offline             4096 0x1000
        NotContentIndexed   8192 0x2000
        Encrypted          16384 0x4000
        IntegrityStream    32768 0x8000
        NoScrubData       131072 0x20000
    .OUTPUTS
        [string[]]
    #>

  [CmdletBinding(ConfirmImpact = 'None')]
  [OutputType([string[]])]
  Param (
    [switch]$IncludeValue
  )

  begin {
    Write-Host $MyInvocation
  }

  process {
    $datatype = 'System.IO.FileAttributes'
    if (-not $IncludeValue) {
      [enum]::GetNames($datatype)
    } else {
      [enum]::Getvalues($datatype) |
        ForEach-Object {
          New-Object -TypeName psobject -Property ([ordered] @{
              Name = $_.toString()
              Dec  = $_.value__
              Hex  = '0x{0:x}' -f ($_.value__)
            }
          )
        }
    }
  }

  end {
    Write-Verbose -Message "Complete."
  }
}
