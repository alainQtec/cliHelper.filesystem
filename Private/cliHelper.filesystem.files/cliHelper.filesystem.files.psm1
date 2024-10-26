using namespace System;
using namespace System.IO;

class FileExtensionInfo {
  [string]$Path
  [string]$Extension
  [int]$Count
  [int]$TotalSize
  [int]$SmallestSize
  [int]$LargestSize
  [int]$AverageSize
  [datetime]$ReportDate
  [FileInfo[]]$Files
  [bool]$IsLargest
  hidden [string]$Computername = [Environment]::MachineName

  static [FileExtensionInfo] Create([hashtable]$Properties) {
    return New-Object -TypeName FileExtensionInfo -Property $Properties
  }
}

class RecentOpenInfo {
  [string]$Name
  [string]$Path
  [string]$href
  [string]$exec
  [string]$modified
  [int]$count

  RecentOpenInfo() {}
  RecentOpenInfo([System.Xml.XmlElement]$info) {
    [void][RecentOpenInfo]::__create($info, [ref]$this)
  }
  static [RecentOpenInfo] Create([System.Xml.XmlElement]$info) {
    $o = [RecentOpenInfo]::new(); return [RecentOpenInfo]::__create($info, [ref]$o)
  }
  static hidden [RecentOpenInfo] __create([System.Xml.XmlElement]$info, [ref]$o) {
    $o.Value.href = $info.href
    $_info = $info.info.metadata.applications.application
    $o.Value.Name = $_info.name
    $o.Value.Path = [Uri]::UnescapeDataString($o.Value.href).Substring(7)
    $o.Value.exec = $_info.exec
    $o.Value.count = $_info.count
    $o.Value.modified = $_info.modified
    return $o.Value
  }
}

function Get-Assoc {
  <#
.SYNOPSIS
    Displays file extension associations
.DESCRIPTION
    Displays file extension associations which can be gotten from cmd.exe
.PARAMETER AsArray
    Switch to return result as an array of objects as opposed to an ordered dictionary
.EXAMPLE
    Get-Assoc

    Name                           Value
    ----                           -----
.EXAMPLE
    Get-Assoc -AsArray | Where-Object { $_.Name -match 'xls' } | Select-Object Value, Name

    Value                            Name
    -----                            ----
    Excel.Sheet.8                    .xls
    Excel.SheetBinaryMacroEnabled.12 .xlsb
    Excelhtmlfile                    .xlshtml
    Excel.SheetMacroEnabled.12       .xlsm
    excelmhtmlfile                   .xlsmhtml
    Excel.Sheet.12                   .xlsx
#>

  [CmdletBinding()]
  param (
    [switch] $AsArray
  )

  begin {
    Write-Host $MyInvocation
  }

  process {
    $CmdReturn = (cmd.exe /c assoc)
    $GetAssoc = ([ordered] @{})
    foreach ($CurItem in $CmdReturn) {
      $Temp = $CurItem.Split('=')
      $GetAssoc.Add($Temp[0], $Temp[1])
    }
    if ($AsArray) {
      $ArrayOutput = $GetAssoc.GetEnumerator() | ForEach-Object {
        New-Object -TypeName psobject -Property ([ordered] @{
            Name  = $_.Name
            Value = $_.Value
          })
      }
      Write-Output -InputObject $ArrayOutput
    } else {
      Write-Output -InputObject $GetAssoc
    }
  }

  end {
    Write-Verbose -Message "Complete."
  }
}


function Enable-FileVersioning {
  <#
    .SYNOPSIS
        A short one-line action-based description, e.g. 'Tests if a function is valid'
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        http://v65ngaoj2nyaiq2ltf4uzota254gnasarrkuj4aqndi2bb5lw6frt3ad.onion/entry/how-to-windows-file-versioning.html
    .EXAMPLE
        Test-MyTestFunction -Verbose
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
  [CmdletBinding()]
  param (

  )

  begin {
  }

  process {
  }

  end {
  }
}

function Get-FileWithLeadingSpace {
  # .SYNOPSIS
  #     To find files that begin with a space character
  # .DESCRIPTION
  #     To find files that begin with a space character
  # .PARAMETER Path
  #     The path where you want to begin looking
  # .EXAMPLE
  #     Get-FileWithLeadingSpace -path Value
  #     Describe what this call does  [CmdletBinding(ConfirmImpact = 'None')]
  Param([string] $Path = $PWD)

  begin {
    Write-Host $MyInvocation
  }

  process {
    Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue |
      ForEach-Object {
        if ($_.name.length -ne $_.name.trim().length) {
          Write-Output -InputObject $_.FullName
        }
      }
  }

  end {
    Write-Verbose -Message "Complete."
  }
}


function Copy-WithProgress {
  <#
    .SYNOPSIS
        A short one-line action-based description, e.g. 'Tests if a function is valid'
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        From Original Post: https://stackoverflow.com/a/21209726/16289046
    .EXAMPLE
        # 1. TESTING: Generate a random, unique source directory, with some test files in it
        $TestSource = '{0}\{1}' -f $env:temp, [Guid]::NewGuid().ToString();
        $null = mkdir -Path $TestSource;
        # 1a. TESTING: Create some test source files
        1..20 | ForEach-Object -Process { Set-Content -Path $TestSource\$_.txt -Value ('A' * (Get-Random -Minimum 10 -Maximum 2100)); };

        # 2. TESTING: Create a random, unique target directory
        $TestTarget = '{0}\{1}' -f $env:temp, [Guid]::NewGuid().ToString();
        $null = mkdir -Path $TestTarget;

        # 3. Call the Copy-WithProgress function
        Copy-WithProgress -Source $TestSource -Destination $TestTarget -Verbose;

        # 4. Add some new files to the source directory
        21..40 | ForEach-Object -Process { Set-Content -Path $TestSource\$_.txt -Value ('A' * (Get-Random -Minimum 950 -Maximum 1400)); };

        # 5. Call the Copy-WithProgress function (again)
        Copy-WithProgress -Source $TestSource -Destination $TestTarget -Verbose;
    #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string] $Source,
    [Parameter(Mandatory = $true)]
    [string] $Destination,
    [int] $Gap = 200,
    [int] $ReportGap = 2000
  )
  # Define regular expression that will gather number of bytes copied
  $RegexBytes = '(?<=\s+)\d+(?=\s+)';

  #region Robocopy params
  # MIR = Mirror mode
  # NP  = Don't show progress percentage in log
  # NC  = Don't log file classes (existing, new file, etc.)
  # BYTES = Show file sizes in bytes
  # NJH = Do not display robocopy job header (JH)
  # NJS = Do not display robocopy job summary (JS)
  # TEE = Display log in stdout AND in target log file
  $CommonRobocopyParams = '/MIR /NP /NDL /NC /BYTES /NJH /NJS';
  #endregion Robocopy params

  #region Robocopy Staging
  Write-Verbose 'Analyzing robocopy job ...';
  $StagingLogPath = '{0}\temp\{1} robocopy staging.log' -f $env:windir, (Get-Date -Format 'yyyy-MM-dd HH-mm-ss');

  $StagingArgumentList = '"{0}" "{1}" /LOG:"{2}" /L {3}' -f $Source, $Destination, $StagingLogPath, $CommonRobocopyParams;
  Write-Verbose ('Staging arguments: {0}' -f $StagingArgumentList);
  Start-Process -Wait -FilePath robocopy.exe -ArgumentList $StagingArgumentList -NoNewWindow;
  # Get the total number of files that will be copied
  $StagingContent = Get-Content -Path $StagingLogPath;
  $TotalFileCount = $StagingContent.Count - 1;

  # Get the total number of bytes to be copied
  $BytesTotal = 0
  [RegEx]::Matches(($StagingContent -join "`n"), $RegexBytes) | ForEach-Object { $BytesTotal += $_.Value; };
  Write-Verbose ('Total bytes to be copied: {0}' -f $BytesTotal);
  #endregion Robocopy Staging

  #region Start Robocopy
  # Begin the robocopy process
  $RobocopyLogPath = '{0}\temp\{1} robocopy.log' -f $env:windir, (Get-Date -Format 'yyyy-MM-dd HH-mm-ss');
  $ArgumentList = '"{0}" "{1}" /LOG:"{2}" /ipg:{3} {4}' -f $Source, $Destination, $RobocopyLogPath, $Gap, $CommonRobocopyParams;
  Write-Verbose ('Beginning the robocopy process with arguments: {0}' -f $ArgumentList);
  $Robocopy = Start-Process -FilePath robocopy.exe -ArgumentList $ArgumentList -Verbose -PassThru -NoNewWindow;
  Start-Sleep -Milliseconds 100;
  #endregion Start Robocopy

  #region Progress bar loop
  while (!$Robocopy.HasExited) {
    Start-Sleep -Milliseconds $ReportGap;
    $BytesCopied = 0;
    $LogContent = Get-Content -Path $RobocopyLogPath;
    $BytesCopied = [Regex]::Matches($LogContent, $RegexBytes) | ForEach-Object -Process { $BytesCopied += $_.Value; } -End { $BytesCopied; };
    $CopiedFileCount = $LogContent.Count - 1;
    Write-Verbose ('Bytes copied: {0}' -f $BytesCopied);
    Write-Verbose ('Files copied: {0}' -f $LogContent.Count);
    $Percentage = 0;
    if ($BytesCopied -gt 0) {
      $Percentage = (($BytesCopied / $BytesTotal) * 100)
    }
    Write-Progress -Activity Robocopy -Status ("Copied {0} of {1} files; Copied {2} of {3} bytes" -f $CopiedFileCount, $TotalFileCount, $BytesCopied, $BytesTotal) -PercentComplete $Percentage
  }
  #endregion Progress loop

  #region Function output
  [PSCustomObject]@{
    BytesCopied = $BytesCopied;
    FilesCopied = $CopiedFileCount;
  };
  #endregion Function output
}

function Get-FileMetaData {
  # .SYNOPSIS
  # 	Get File MetaData
  # .DESCRIPTION
  # 	A detailed description of the Get-MetaData function.

  # .PARAMETER FileName
  # 	Name of File

  # .EXAMPLE
  # 	PS C:\> Get-MetaData -FileName 'Value1'

  # .NOTES
  # 	Additional information about the function.
  [CmdletBinding()][OutputType([object])]
  param(
    [ValidateNotNullOrEmpty()][string]$FileName
  )

  $MetaDataObject = New-Object System.Object
  $shell = New-Object -COMObject Shell.Application
  $folder = Split-Path $FileName
  $file = Split-Path $FileName -Leaf
  $shellfolder = $shell.Namespace($folder)
  $shellfile = $shellfolder.ParseName($file)
  $MetaDataProperties = 0..287 | ForEach-Object { '{0} = {1}' -f $_, $shellfolder.GetDetailsOf($null, $_) }
  for ($i = 0; $i -le 287; $i++) {
    $Property = ($MetaDataProperties[$i].split("="))[1].Trim()
    $Property = (Get-Culture).TextInfo.ToTitleCase($Property).Replace(' ', '')
    $Value = $shellfolder.GetDetailsOf($shellfile, $i)
    if ($Property -eq 'Attributes') {
      switch ($Value) {
        'A' {
          $Value = 'Archive (A)'
        }
        'D' {
          $Value = 'Directory (D)'
        }
        'H' {
          $Value = 'Hidden (H)'
        }
        'L' {
          $Value = 'Symlink (L)'
        }
        'R' {
          $Value = 'Read-Only (R)'
        }
        'S' {
          $Value = 'System (S)'
        }
      }
    }
    #Do not add metadata fields which have no information
    if (($null -ne $Value) -and ($Value -ne '')) {
      $MetaDataObject | Add-Member -MemberType NoteProperty -Name $Property -Value $Value
    }
  }
  [string]$FileVersionInfo = (Get-ItemProperty $FileName).VersionInfo
  $SplitInfo = $FileVersionInfo.Split([char]13)
  foreach ($Item in $SplitInfo) {
    $Property = $Item.Split(":").Trim()
    switch ($Property[0]) {
      "InternalName" {
        $MetaDataObject | Add-Member -MemberType NoteProperty -Name InternalName -Value $Property[1]
      }
      "OriginalFileName" {
        $MetaDataObject | Add-Member -MemberType NoteProperty -Name OriginalFileName -Value $Property[1]
      }
      "Product" {
        $MetaDataObject | Add-Member -MemberType NoteProperty -Name Product -Value $Property[1]
      }
      "Debug" {
        $MetaDataObject | Add-Member -MemberType NoteProperty -Name Debug -Value $Property[1]
      }
      "Patched" {
        $MetaDataObject | Add-Member -MemberType NoteProperty -Name Patched -Value $Property[1]
      }
      "PreRelease" {
        $MetaDataObject | Add-Member -MemberType NoteProperty -Name PreRelease -Value $Property[1]
      }
      "PrivateBuild" {
        $MetaDataObject | Add-Member -MemberType NoteProperty -Name PrivateBuild -Value $Property[1]
      }
      "SpecialBuild" {
        $MetaDataObject | Add-Member -MemberType NoteProperty -Name SpecialBuild -Value $Property[1]
      }
    }
  }

  #Check if file is read-only
  $ReadOnly = (Get-ChildItem $FileName) | Select-Object IsReadOnly
  $MetaDataObject | Add-Member -MemberType NoteProperty -Name ReadOnly -Value $ReadOnly.IsReadOnly
  #Get digital file signature information
  $DigitalSignature = Get-AuthenticodeSignature -FilePath $FileName
  $MetaDataObject | Add-Member -MemberType NoteProperty -Name SignatureCertificateSubject -Value $DigitalSignature.SignerCertificate.Subject
  $MetaDataObject | Add-Member -MemberType NoteProperty -Name SignatureCertificateIssuer -Value $DigitalSignature.SignerCertificate.Issuer
  $MetaDataObject | Add-Member -MemberType NoteProperty -Name SignatureCertificateSerialNumber -Value $DigitalSignature.SignerCertificate.SerialNumber
  $MetaDataObject | Add-Member -MemberType NoteProperty -Name SignatureCertificateNotBefore -Value $DigitalSignature.SignerCertificate.NotBefore
  $MetaDataObject | Add-Member -MemberType NoteProperty -Name SignatureCertificateNotAfter -Value $DigitalSignature.SignerCertificate.NotAfter
  $MetaDataObject | Add-Member -MemberType NoteProperty -Name SignatureCertificateThumbprint -Value $DigitalSignature.SignerCertificate.Thumbprint
  $MetaDataObject | Add-Member -MemberType NoteProperty -Name SignatureStatus -Value $DigitalSignature.Status
  return $MetaDataObject
}


function New-Tempfile {
  <#
    .SYNOPSIS
        Creates a temporary file.
    .DESCRIPTION
        This function creates temporary files that you can use in scripts.
        Basically this is `New-TemporaryFile` cmdlet but with much more options
    .EXAMPLE
        New-Tempfile
        "creates an empty file that has no file name extension."
    .EXAMPLE
        $tfile = New-Tempfile -xt .ps1
        "Now you can use the fullname: $($tfile.FullName) `nand do much more since `$tfile is a [IO.FileInfo] object."
        "creates an empty file that has the `.ps1` file name extension."
    .EXAMPLE
        New-Tempfile -Prefix I\nvalid:Prefix/Name.-* -Ext tmp -Verbose -Debug
        "creates an empty file with a .tmp file extension and a prefix name. The preffix is invalid so it gets fixed."
    .INPUTS
        [string]
    .OUTPUTS
        [IO.FileInfo]
    .LINK
        https://gist.github.com/alainQtec/3796a9f93733f566893a3226d777293a
    .LINK
        https://github.com/alainQtec/cliHelper.filesystem/blob/main/Public/New-Tempfile.ps1
    #>
  [CmdletBinding(SupportsShouldProcess)]
  param (
    [Parameter(Mandatory = $false, Position = 0)]
    [Alias('Pref', 'p')]
    [string]$Prefix,

    [Parameter(Mandatory = $false, Position = 1)]
    [Alias('Ext', 'xt')]
    [string]$Extension,

    [Parameter(Mandatory = $false, Position = 2)]
    [ValidateSet("Guid", "String", "Numbers", "None")]
    [Alias('Style', 'ns')]
    [string]$NameStyle = 'None',

    [Parameter(Mandatory = $false, Position = 3)]
    [Alias('Parent', 'Directory', 'Destination')]
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
    [string]$ParentPath = [IO.Path]::GetTempPath()
  )

  DynamicParam {
    $DynamicParams = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
    $attributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
    $attributes = [System.Management.Automation.ParameterAttribute]::new(); $attHash = @{
      Position                        = 4
      ParameterSetName                = '__AllParameterSets'
      Mandatory                       = $False
      ValueFromPipeline               = $true
      ValueFromPipelineByPropertyName = $true
      ValueFromRemainingArguments     = $true
      HelpMessage                     = 'Allows splatting with arguments that do not apply. Do not use directly.'
      DontShow                        = $False
    }; $attHash.Keys | ForEach-Object { $attributes.$_ = $attHash.$_ }
    $attributeCollection.Add($attributes)
    # $attributeCollection.Add([System.Management.Automation.ValidateSetAttribute]::new([System.Object[]]$ValidateSetOption))
    # $attributeCollection.Add([System.Management.Automation.ValidateRangeAttribute]::new([System.Int32[]]$ValidateRange))
    # $attributeCollection.Add([System.Management.Automation.ValidateNotNullOrEmptyAttribute]::new())
    # $attributeCollection.Add([System.Management.Automation.AliasAttribute]::new([System.String[]]$Aliases))
    $RuntimeParam = [System.Management.Automation.RuntimeDefinedParameter]::new("IgnoredArguments", [Object[]], $attributeCollection)
    $DynamicParams.Add("IgnoredArguments", $RuntimeParam)
    return $DynamicParams
  }

  Begin {
    $fxn = ('[' + $MyInvocation.MyCommand.Name + ']')
    $PsCmdlet.MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value -ea 'SilentlyContinue' }
    $eap = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
  }

  process {
    if (![string]::IsNullOrEmpty($ParentPath)) {
      try {
        $ParentPath = Resolve-Path $ParentPath
      } catch {
        $null
      }
      if (!(Test-Path $ParentPath -PathType Container -ErrorAction SilentlyContinue) -or ![IO.Path]::IsPathFullyQualified($ParentPath)) {
        $ParentPath = $null
      }
    } elseif ($ParentPath -eq [string]::Empty) {
      $ParentPath = $null
    }
    # TODO: Make this cross-platform. On non-Windows: Use the path specified by the TMPDIR environment variable.
    if ($PSBoundParameters.ContainsKey('Prefix')) {
      Write-Verbose -Message "[+] Try remove Suspicious characters from prefix ..."
      $Prefix = & {
        try {
          return [regex]::Replace("$prefix", "[^\w\.@-]", '', [System.Text.RegularExpressions.RegexOptions]::None, [timespan]::FromMilliseconds(1));
        } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
          # Suspicious characters
          [PSCustomObject]$Suss = 1..126 | Where-Object { $([IO.Path]::GetInvalidFileNameChars()).Contains([char]$_) } | Select-Object @{l = 'Char'; e = { [char]$_ } }, @{l = 'code'; e = { $_ } }
          [String[]]$IllegalChars = $Suss.char
          [string[]][char[]]$Prefix | Where-Object { !$IllegalChars.Contains($_) } | ForEach-Object { $p += $_ };
          return $p
        } catch {
          return [string]::Empty
        }
      }
      if ($Prefix -eq [string]::Empty) {
        Write-Verbose -Message "Failed to remove invalid characters from prefix! [+] Generating New One ...`n"
        $Prefix = [IO.Path]::GetFileNameWithoutExtension([IO.Path]::GetRandomFileName())
      }
      Write-Verbose -Message "[+] Prefix name was changed to : $Prefix"
    }
    $pxt = [Char]46 + [Char]63 # The placeholder extension. Used when user didn't Specify use of any extention. [It will be removed after tempfile name is created.]
    if ($PSBoundParameters.ContainsKey('Extension')) {
      if (!$Extension.StartsWith($46)) { $Extension = [Char]46 + $Extension }
    } else {
      $Extension = $pxt
    }
    if (!$PSBoundParameters.ContainsKey('NameStyle')) { $NameStyle = 'none' }
    Write-Verbose -Message "⏳ Generating TempFile name ..."
    switch ($NameStyle) {
      Guid { do { $tmp = [IO.Path]::Combine($ParentPath, [IO.path]::ChangeExtension($Prefix + (New-Guid).Guid.trim(), "$Extension")) } until (![IO.File]::Exists($tmp) -and ![IO.File]::Exists($tmp.Replace($Extension, '').TrimEnd())); Break }
      String { do { $tmp = [IO.Path]::Combine($ParentPath, [IO.path]::ChangeExtension($Prefix + (New-Guid).Guid.trim().Replace('-', "$(Get-Random 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')"), "$Extension")) } until (![IO.File]::Exists($tmp)); Break }
      Numbers { do { $tmp = [IO.Path]::Combine($ParentPath, [IO.path]::ChangeExtension($Prefix + (Get-Random -Maximum 1000000000000000000) + (Get-Random -Maximum 1000000000000000000), "$Extension")) } until (![IO.File]::Exists($tmp) -and ![IO.File]::Exists($tmp.Replace($Extension, '').TrimEnd())); Break }
      Default {
        Write-Verbose -Message "[+] No naming style was specified. Using RandomFileName .."
        do { $tmp = [IO.Path]::Combine($ParentPath, [IO.path]::ChangeExtension($Prefix + [IO.Path]::GetRandomFileName(), "$Extension")) } until (![IO.File]::Exists($tmp) -and ![IO.File]::Exists($tmp.Replace($Extension, '').TrimEnd()));
      }
    }
    if ([IO.path]::GetExtension($tmp) -eq $pxt) { $tmp = $tmp.Replace($pxt, '').TrimEnd() }
    if ($PSCmdlet.ShouldProcess("$fxn ⏳ Performing the operation `"New-Item`" on target `"$tmp`" ", '$tmp', 'New-Item')) {
      [IO.FileInfo]$tmpFile = $(New-Item -Path $tmp -Type File | Get-Item)
    }
  }

  end {
    Write-Verbose -Message "✅ Done."
    $ErrorActionPreference = $eap;
    return $tmpFile
  }
}



function Search-InFiles {
  # .SYNOPSIS
  # 	Searches for a pattern in files
  # .DESCRIPTION
  # 	This PowerShell script searches for a pattern in the given files.
  # .PARAMETER pattern
  # 	Specifies the search pattern
  # .PARAMETER files
  # 	Specifies the files
  # .EXAMPLE
  # 	PS> Search-InFiles UFO C:\Temp\*.txt
  [CmdletBinding()]
  param (
    [string]$pattern = "",
    [string]$files = ""
  )

  begin {
    function ListLocations {
      param([string]$Pattern, [string]$Path)
      $List = Select-String -Path $Path -Pattern "$Pattern"
      foreach ($Item in $List) {
        New-Object PSObject -Property @{
          'Path' = "$($Item.Path)"
          'Line' = "$($Item.LineNumber)"
          'Text' = "$($Item.Line)"
        }
      }
      Write-Output "(found $($List.Count) locations with pattern '$pattern')"
    }
  }

  process {
    try {
      if ($pattern -eq "" ) { $pattern = Read-Host "Enter search pattern" }
      if ($files -eq "" ) { $files = Read-Host "Enter path to files" }

      ListLocations $pattern $files | Format-Table -Property Path, Line, Text
      # success
    } catch {
      # Write-Log $_.Exception.ErrorRecord
      Write-Verbose -Message "Errored: $($_.CategoryInfo.Category) : $($_.CategoryInfo.Reason) : $($_.Exception.Message)"
      break
    }
  }
}