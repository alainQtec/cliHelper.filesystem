function Get-Drives {
  # .SYNOPSIS
  # Lists all drives
  [CmdletBinding()]
  param ()

  process {
    try {
      return Get-PSDrive -PSProvider FileSystem | Format-Table -Property Name, Root, @{n = "Used (GB)"; e = { [math]::Round($_.Used / 1GB, 1) } }, @{n = "Free (GB)"; e = { [math]::Round($_.Free / 1GB, 1) } }
      # success
    } catch {
      $PSCmdlet.ThrowTerminatingError($_)
      # Write-Log $_.Exception.ErrorRecord
      # Write-Verbose -Message "Errored: $($_.CategoryInfo.Category) : $($_.CategoryInfo.Reason) : $($_.Exception.Message)"
    }
  }
}

function Get-AvailableDriveLetter {
  # .SYNOPSIS
  #   Get a 'free' drive letter

  # .DESCRIPTION
  #   Get a not yet in-use drive letter that can be used for mounting

  # .EXAMPLE
  #   Get-AvailableDriveLetter

  # .EXAMPLE
  #   Get-AvailableDriveLetter 'X'
  #   (do not return X, even if it'd be the next choice)

  # .INPUTS
  #   specific drive letter(s) that will be excluded as potential candidates

  # .OUTPUTS
  #   System.String (single drive-letter character)

  # .LINK
  #   http://stackoverflow.com/questions/12488030/getting-a-free-drive-letter/29373301#29373301
  param (
    [char[]]$ExcludedLetters,

    # Allows splatting with arguments that do not apply and future expansion. Do not use directly.
    [parameter(ValueFromRemainingArguments = $true)]
    [Object[]] $IgnoredArguments
  )

  $Letter = [int][char]'C'
  $i = @()

  #getting all the used Drive letters reported by the Operating System
  $(Get-PSDrive -PSProvider filesystem) | ForEach-Object { $i += $_.name }

  #Adding the excluded letter
  $i += $ExcludedLetters

  while ($i -contains $([char]$Letter)) { $Letter++ }

  if ($Letter -gt [char]'Z') {
    throw "error: no drive letter available!"
  }
  Write-Verbose "available drive letter: '$([char]$Letter)'"
  Return $([char]$Letter)
}

function Debug-DiskHealth {
  <#
  .SYNOPSIS
    Analyse and points out disk Health Faults
  #>
  [CmdletBinding( SupportsShouldProcess = $true, DefaultParameterSetName = "ByDriveLetter" )]
  Param
  (
    [char[]]
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true,
      ParameterSetName = "ByDriveLetter",
      Position = 0)]
    $DriveLetter,

    [string[]]
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true,
      ParameterSetName = "ById")]
    $ObjectId,

    [string[]]
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true,
      ParameterSetName = "ByPaths")]
    $Path,

    [string[]]
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true,
      ParameterSetName = "ByLabel"
    )]
    [Alias("FriendlyName")]
    $FileSystemLabel,

    [Microsoft.Management.Infrastructure.CimInstance]
    [PSTypeName("Microsoft.Management.Infrastructure.CimInstance#ROOT/Microsoft/Windows/Storage/MSFT_Volume")]
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true,
      ParameterSetName = "InputObject")]
    $InputObject,

    [Microsoft.Management.Infrastructure.CimSession]
    [Parameter(
      Mandatory = $false
    )]
    $CimSession,

    # Provided for compatibility with CDXML cmdlets, not actually used.
    [Int32]
    [Parameter(
      Mandatory = $false
    )]
    $ThrottleLimit,
    [Switch]
    [Parameter(
      Mandatory = $false
    )]
    $AsJob
  )
  Begin {
    Write-Warning "This cmdlet is deprecated and may not be
              available in the future. Use Get-HealthFault instead."
  }
  Process {
    $info = $resources.info
    $p = $null

    if (-not $CimSession) {
      $CimSession = New-CimSession
    }
    switch ($PsCmdlet.ParameterSetName) {
      "ByDriveLetter" { $io = Get-Volume -CimSession $CimSession -DriveLetter $DriveLetter -ErrorAction stop; break; }
      "ById" { $io = Get-Volume -CimSession $CimSession -ObjectId $ObjectId -ErrorAction stop; break; }
      "ByPaths" { $io = Get-Volume -CimSession $CimSession -Path $Path -ErrorAction stop; break; }
      "ByLabel" { $io = Get-Volume -CimSession $CimSession -FileSystemLabel $FileSystemLabel -ErrorAction stop; break; }
    }
    # Would use a closure here, but jobs are run in their own session state.
    $block = {
      param($session, $asjob, $io)

      # Start-Job serializes/deserializes the CimSession,
      # which means it shows up here as having type Deserialized.CimSession.
      # Must recreate or cast the object in order to pass it to Get-CimInstance.
      if ($asjob) {
        $session = $session | New-CimSession
      }
      $result = @()
      $output = Invoke-CimMethod -MethodName Diagnose -InputObject $io -CimSession $session
      foreach ($i in $output) { $result += $i.ItemValue }
      $result | Sort-Object -Property PerceivedSeverity
    }

    if ($asjob) {
      $p = $true
      Start-Job -ScriptBlock $block -ArgumentList @($CimSession, $p, $InputObject)
    } else {
      if ($pscmdlet.ShouldProcess($info, $resources.warning, $info)) {
        &$block $CimSession $p $InputObject
      }
    }
  }
}

