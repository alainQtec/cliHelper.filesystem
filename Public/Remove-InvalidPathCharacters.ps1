function Remove-InvalidPathCharacters {
  <#
    .SYNOPSIS
        Removes Suspicious characters from file or folder Names
    .DESCRIPTION
        Removes Suspicious characters from file or folder Names
    .EXAMPLE
        Remove-InvalidPathCharacters "C:\Users\Alain\SolitaireGame♥♦♣♠Folder\"
    .LINK
        https://github.com/alainQtec/cliHelper.filesystem/blob/main/Public/Remove-InvalidPathCharacters.ps1
    #>
  [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'File')]
  [OutputType([string])]
  param (
    # File Name, you can also Use FullPath/FullName. Use tab completion to choose which File
    [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'File', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [alias('File')]
    [ArgumentCompleter({
        [OutputType([System.Management.Automation.CompletionResult])]
        param(
          [string]$CommandName,
          [string]$ParameterName,
          [string]$WordToComplete,
          [System.Management.Automation.Language.CommandAst]$CommandAst,
          [System.Collections.IDictionary]$FakeBoundParameters
        )
        $CompletionResults = [System.Collections.Generic.List[System.Management.Automation.CompletionResult]]::new()
        $(Get-ChildItem | Where-Object { !$_.PSIsContainer }).Name | Where-Object { $_ -like "*$wordToComplete*" } | ForEach-Object {
          $CompletionResults.Add([System.Management.Automation.CompletionResult]::new($_, $_, "ParameterValue", $_))
        }
        return $CompletionResults
      }
    )]
    [string]$FileName,
    # Folder Name, you can also Use FullPath/FullName. Use tab completion to choose which Folder
    [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'Directory', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [alias('Folder', 'Directory')]
    [ArgumentCompleter({
        [OutputType([System.Management.Automation.CompletionResult])]
        param(
          [string]$CommandName,
          [string]$ParameterName,
          [string]$WordToComplete,
          [System.Management.Automation.Language.CommandAst]$CommandAst,
          [System.Collections.IDictionary]$FakeBoundParameters
        )
        $CompletionResults = [System.Collections.Generic.List[System.Management.Automation.CompletionResult]]::new()
        $(Get-ChildItem | Where-Object { $_.PSIsContainer }).Name | Where-Object { $_ -like "*$wordToComplete*" } | ForEach-Object {
          $CompletionResults.Add([System.Management.Automation.CompletionResult]::new($_, $_, "ParameterValue", $_))
        }
        return $CompletionResults
      }
    )]
    [string]$FolderName
  )

  Begin {
    if ($PSCmdlet.ParameterSetName.Equals('File')) {
      Write-Host "PSETnAME = file"
      if ($null -eq $PSBoundParameters["FileName"] -or $PSBoundParameters["FileName"] -eq '') {
        "No FILEname Parameter"
      }
    } elseif ($PSCmdlet.ParameterSetName.Equals('Directory')) {
      Write-Host "PSETnAME = Directory"
      if ($null -eq $PSBoundParameters["FolderName"] -or $PSBoundParameters["FolderName"] -eq '') {
        "No folderNAME Parameter"
      }
    }
    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { if (![bool][IO.Path]::IsPathFullyQualified($_)) {
        $PSCmdlet.MyInvocation.BoundParameters[$_] = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($_)
      }
    }
    $ItemType = $PSCmdlet.ParameterSetName + 'Name'
    Write-Output "`$ItemName = [$ItemName]"
    Write-Output "`$ItemType = $ItemType"
    #  $destinationPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
    Pause
    break
    # if ($ItemName.EndsWith($([IO.Path]::DirectorySeparatorChar))) {
    #     $PsetName = 'Directory'
    # } else {
    #     $PsetName = 'File'
    # }
  }

  process {
    if ($PSCmdlet.ParameterSetName -eq 'File') {
      Write-Host "PSETnAME = file"
      $InvalidChars = [IO.Path]::GetInvalidFileNameChars()
      $ItemName = $FileName
    } else {
      Write-Host "PSETnAME = dIRECTORY"
      $InvalidChars = [IO.Path]::GetInvalidPathChars()
      $ItemName = $FolderName
    }
    "FolderName = $FolderName"
    "FileName   = $FileName"
    # $ItemName = @(if ([IO.Path]::IsPathFullyQualified($ItemName)) { $ItemName.split($([IO.Path]::DirectorySeparatorChar)) } else { $ItemName })
    # $ItemName.Count

    $result = & {
      try {
        if ($PSCmdlet.ShouldProcess("$ItemType : '$ItemName'", "[regex]::Replace()")) {
          [regex]::Replace("$ItemName", "[^\w\.@-]", '', [System.Text.RegularExpressions.RegexOptions]::None, [timespan]::FromMilliseconds(1));
        }
      } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
        [string]::Empty
      } catch {
        $SUS = @(); 1..126 | Where-Object { $InvalidChars.Contains([char]$_) } | ForEach-Object { $SUS += [PSCustomObject]@{ Char = [char]$_ ; code = $_ } }
        if ($PSCmdlet.ShouldProcess("$ItemType : '$ItemName'", "Filter SUS chars")) {
          $([string[]][char[]]$ItemName | Where-Object { !$SUS.Char.Contains($_) }) -join ''
        }
      }
    }
  }

  end {
    return $result
  }
}