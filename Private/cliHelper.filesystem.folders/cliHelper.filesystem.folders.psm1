using namespace System;
using namespace System.IO;
using namespace System.Collections.Generic;
using namespace System.Text.RegularExpressions;
using namespace System.Collections.Specialized;


class FileSystemWatcherHelper {
  FileSystemWatcherHelper() {}
}

class FolderSizeInfo {
  [string]$Path
  [string]$Name
  [int]$TotalFiles
  [int]$TotalSize
  hidden [string]$Computername = [Environment]::MachineName

  static [FolderSizeInfo] Create([hashtable]$Properties) {
    return New-Object -TypeName FolderSizeInfo -Property $Properties
  }
}

<#
.Synopsis
	File change watcher and handler.
	Author: Roman Kuzmin

.Description
	The script watches for changed, created, deleted, and renamed files in the
	given directories. On changes it invokes the specified command with change
	info. It is a dictionary where keys are changed file paths, values are last
	change types.

	If the command is omitted then the script outputs change info as text.

	The script works until it is forcedly stopped (Ctrl-C).

.Parameter Path
		Specifies the watched directory paths.
.Parameter Command
		Specifies the command to process changes.
		It may be a script block or a command name.
.Parameter Filter
		Simple and effective file system filter. Default *.*
.Parameter Include
		Inclusion regular expression pattern applied after Filter.
.Parameter Exclude
		Exclusion regular expression pattern applied after Filter.
.Parameter Recurse
		Tells to watch files in subdirectories as well.
.Parameter TestSeconds
		Time to sleep between checks for change events.
.Parameter WaitSeconds
		Time to wait after the last change before processing.

.Link
	https://github.com/nightroman/PowerShelf
#>


# param(
#   [Parameter(Position = 1, Mandatory = 1)]
#   [string[]]$Path,
#   [Parameter(Position = 2)]
#   $Command,
#   [string]$Filter,
#   [string]$Include,
#   [string]$Exclude,
#   [switch]$Recurse,
#   [int]$TestSeconds = 5,
#   [int]$WaitSeconds = 5
# )

# trap { $PSCmdlet.ThrowTerminatingError($_) }

# $Path = foreach ($_ in $Path) {
#   $_ = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($_)
#   if (!([System.IO.Directory]::Exists($_))) {
#     throw "Missing directory: $_"
#   }
#   $_
# }
<#
Add-Type @'


public class FileSystemWatcherHelper : IDisposable
{
	public string[] Path;
	public string Filter;
	public bool Recurse;

	public DateTime LastTime { get { return _lastTime; } }
	public bool HasChanges { get { return _changes.Count > 0; } }

	OrderedDictionary _changes = new OrderedDictionary();
	readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
	readonly object _lock = new object();
	DateTime _lastTime;
	Regex _include;
	Regex _exclude;

	public void Include(string pattern)
	{
		if (!string.IsNullOrEmpty(pattern))
			_include = new Regex(pattern, RegexOptions.IgnoreCase);
	}
	public void Exclude(string pattern)
	{
		if (!string.IsNullOrEmpty(pattern))
			_exclude = new Regex(pattern, RegexOptions.IgnoreCase);
	}
	public void Start()
	{
		foreach (string p in Path)
		{
			FileSystemWatcher watcher = new FileSystemWatcher(p);
			_watchers.Add(watcher);

			watcher.IncludeSubdirectories = Recurse;
			watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite;
			if (!string.IsNullOrEmpty(Filter))
				watcher.Filter = Filter;

			watcher.Created += OnChanged;
			watcher.Changed += OnChanged;
			watcher.Deleted += OnChanged;
			watcher.Renamed += OnChanged;
			watcher.EnableRaisingEvents = true;
		}
	}
	public object GetChanges()
	{
		lock (_lock)
		{
			object r = _changes;
			_changes = new OrderedDictionary();
			return r;
		}
	}
	public void Dispose()
	{
		foreach (FileSystemWatcher watcher in _watchers)
			watcher.Dispose();
		_watchers.Clear();
		_changes.Clear();
	}
	void OnChanged(object sender, FileSystemEventArgs e)
	{
		if (_include != null && !_include.IsMatch(e.Name))
			return;

		if (_exclude != null && _exclude.IsMatch(e.Name))
			return;

		lock (_lock)
		{
			_changes[e.FullPath] = e.ChangeType;
			_lastTime = DateTime.Now;
		}
	}
}
'@

$watcher = New-Object FileSystemWatcherHelper
$watcher.Path = $Path
$watcher.Filter = $Filter
$watcher.Recurse = $Recurse
try { $watcher.Include($Include) } catch { throw "Parameter Include: $_" }
try { $watcher.Exclude($Exclude) } catch { throw "Parameter Exclude: $_" }
try {
  $watcher.Start()
  for () {
    Start-Sleep -Seconds $TestSeconds

    if (!$watcher.HasChanges) { continue }
    if (([datetime]::Now - $watcher.LastTime).TotalSeconds -lt $WaitSeconds) { continue }

    $changes = $watcher.GetChanges()
    if ($Command) {
      try {
        & $Command $changes
      } catch {
        "$($_.ToString())`r`n$($_.InvocationInfo.PositionMessage)"
      }
    } else {
      foreach ($kv in $changes.GetEnumerator()) {
        "$($kv.Value) $($kv.Key)"
      }
    }
  }
} finally {
  $watcher.Dispose()
}
#>



function goto {
  <#
    .SYNOPSIS
        Quickly goto any folder in the terminal
    .DESCRIPTION
        You can save your favourite folders as nickname, thus use those short names to quickly move though folders.
    .EXAMPLE
        PS C:\> goto
        Explanation of what the example does
    .INPUTS
        [string]
    .OUTPUTS
        Null
    .LINK
        Online version : https://github.com/alainQtec/cliHelper.filesystem/blob/main/Public/goto.ps1
        Author Site    : https://alainQtec.com/
    #>
  [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = "Name")]
  [OutputType([string])]
  param (
    [Parameter(Mandatory = $false,
      Position = 0,
      ParameterSetName = "Path",
      ValueFromPipeline = $true,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Path to the location. Wildcards are permitted; Type Goto to check available Paths.")]
    [Alias("PSPath", "p")]
    [ValidateNotNullOrEmpty()]
    [SupportsWildcards()]
    [string]$Path,

    [Parameter(Mandatory = $false,
      Position = 0,
      ParameterSetName = "Name",
      ValueFromPipeline = $true,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Name/nickname of the Path to go to.")]
    [Alias("n")]
    [ValidateNotNullOrEmpty()]
    [string[]]$Name,

    [switch]$ListAvailable
  )

  begin {
    $fxn = ('[' + $MyInvocation.MyCommand.Name + ']')
    $oeap = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'
    # Init Default LOCATION list:
    $defaultlist = @()
    $gotolistjson = "$env:USERPROFILE\.gotolist.json"
    # You can Add/Edit default folders here:
    [PSCustomObject]@{
      Desktop  = $([environment]::GetFolderPath('Desktop'))
      Dls      = $(New-Object -ComObject Shell.Application).NameSpace('Shell:Downloads').Self.Path
      Docs     = $([environment]::GetFolderPath('MyDocuments'))
      GitHub   = $(Join-Path -Path "$([environment]::GetFolderPath("MyDocuments"))" -ChildPath "GitHub" -Resolve)
      Home     = $((Get-Item ([environment]::GetFolderPath('Personal'))).Parent.FullName)
      Music    = $([environment]::GetFolderPath('MyMusic'))
      Pictures = $([environment]::GetFolderPath('MyPictures'))
      Tools    = $([environment]::GetFolderPath('CommonAdminTools'))
      Vids     = $([environment]::GetFolderPath('MyVideos'))
    } | Get-Member -MemberType NoteProperty | ForEach-Object { $defaultlist += [PSCustomObject]@{ Name = $_.Name; Path = $_.Definition.substring($_.Name.Length + 8) } }
    function Update-LocationsDictionary {
      <#
            .SYNOPSIS
                Updates LocationsDictionary
            .DESCRIPTION
                Updates LocationsDictionary in $gotolistjson and updates the global $go_locations variable
            .EXAMPLE
                Update-LocationsDictionary
                Will save to default $JsonPath
            .EXAMPLE
                Update-LocationsDictionary -NewEntry @{Nickname = $fullName}
                Will add new Entry to current dictionary $global:go_locations variable, then save to $JsonPath
            .EXAMPLE
                if ([Bool]$(Update-LocationsDictionary)) { Write-Host "Update was succesfull, thus performming Action ..." }
            .LINK
                Import-GotoLocations
            .NOTES
                This is a private function for goto.ps1 only
            #>
      [CmdletBinding(SupportsShouldProcess)]
      Param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PSCustomObject[]]$List = $defaultlist,
        # Path to the 'goto list' JSON.
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]$JsonPath = $gotolistjson,
        [switch]$removeEmpty
      )
      Process {
        $go_locationsGlobal_Exists = $(try { [bool](Get-Variable go_locations -Scope global -ErrorAction SilentlyContinue) } catch [System.Management.Automation.ItemNotFoundException] { $false } catch { Write-Host "$fxn`n`nErrorId:`n$(($_.FullyQualifiedErrorId -split ',')[0])" ; $false })
        if (!$go_locationsGlobal_Exists) {
          $result = @()
          if ([System.IO.File]::Exists($gotolistjson)) {
            try {
              Get-Content $JsonPath | ConvertFrom-Json | Get-Member -MemberType NoteProperty | ForEach-Object { $result += [PSCustomObject]@{ Name = $_.Name; Path = $_.Definition.substring($_.Name.Length + 8) } }
              if ($result.Path.Count -le 0) {
                $ErrRecord = New-Error -ErrorId System.Management.Automation.ItemNotFoundException -Category InvalidData -Message "Empty Jsons are not allowed :"
                $PSCmdlet.WriteError($ErrRecord)
                $ErrRecord | Write-Log
              }
            } catch {
              $result = $defaultlist
            }
          } else {
            if ($PSCmdlet.ShouldProcess("$gotolistjson", "Create New File")) {
              New-Item -ItemType File -Path $gotolistjson | Out-Null
            }
            $result = $defaultlist
          }
          if ($PSCmdlet.ShouldProcess("go_locations", "Create New global variable")) {
            New-Variable -Name go_locations -Scope global -Visibility Public -Value $result
          }
        }
        # =====================================================
        $Output = @()
        [Hashtable]$Hash = @{}; $List | ForEach-Object { $Hash[$_.Name] = $_.Path }
        try {
          foreach ($key in $($Hash.keys | Sort-Object)) { $Output += [PSCustomObject]@{Name = $key; Path = $Hash[$key] } }
          $Output = $Output | Sort-Object -Unique Name
          $Output = if ($removeEmpty.IsPresent) { $Output | Where-Object { $_.path -ne [string]::Empty -and $null -ne $_.path -and $_.Name -ne [string]::Empty -and $null -ne $_.Name } } else { $ordered }
          if ($PSCmdlet.ShouldProcess("$JsonPath", "Update LocationsJSON")) {
            $Output | ConvertTo-Json | Out-File $JsonPath
          }
        } catch {
          $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]$_)
        } finally {
          if ($PSCmdlet.ShouldProcess("go_locations", "Update Global variable")) {
            Set-Variable -Name go_locations -Scope global -Visibility Public -Value $Output
          }
        }
      }
    }
    Set-Variable -Name set_Location -Visibility Public -Value $([scriptblock]::Create({
          # Tries to set-Location, when it fails it provide a menu to show similar locations
          param($Location, $InputObj)
          $Location = Resolve-Path $Location
          try {
            if (Test-Path "$Location" -PathType Container) {
              Set-Location "$Location"
            } else {
              $similarLocs = $($Locations | Where-Object { $_ -like "*$InputObj*" })
              $parameters = @{
                ArgumentList = @("Which one of these locations ?", $similarLocs)
                ScriptBlock  = $WriteHelp
              }
              Invoke-Command @parameters
              # TODO: Add an interactive console menu, to quickly choose a locaton
            }
          } catch [System.Management.Automation.ParameterBindingException] {
            Write-Host "$fxn Please provide Valid Path Name!" -ForegroundColor White -BackgroundColor DarkRed
          } catch [System.Management.Automation.ItemNotFoundException] {
            $ErrRecord = New-ErrorRecord -Exception System.IO.DirectoryNotFoundException -Message "$fxn Could Not find Path"
            $PSCmdlet.WriteError($ErrRecord)
            $ErrRecord | Write-Log
          } catch {
            $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]$_)
          }
        }
      )
    )
    Set-Variable -Name WriteHelp -Visibility Public -Value $([scriptblock]::Create({
          [CmdletBinding()]
          param([String]$message, $Inputobject)
          if ($message -ne "" -or $null -ne $Inputobject) {
            Write-Host $message
            Write-Output $Inputobject
          } else {
            $go_locations = Invoke-Command -ScriptBlock $Get_Locations
            $TempFile = $([IO.Path]::GetTempFileName()); $go_locations | Out-File $TempFile; $CurrentLocations = Get-Content $TempFile; try { Remove-Item $TempFile -Force | Out-Null } catch { $null }
            Write-Host "$([char]0x276F)" -NoNewline
            Write-Host "# The following are the default locations:${nl}" -ForegroundColor Green
            Write-Host $CurrentLocations
            Write-Host "$([char]0x276F)" -NoNewline
            Write-Host '# Usage Example:' -ForegroundColor Green
            Write-Host "$([char]0x276F)" -NoNewline
            Write-Host 'goto' -ForegroundColor Yellow -NoNewline
            Write-Host ' dl ; ' -NoNewline
            Write-Host "pwd" -ForegroundColor Yellow
            Write-Host "${nl}Path${nl}----${nl}$($go_locations['dls'])${nl}${nl}"
            Write-Host "# To add more Locations run:${nl}" -ForegroundColor Green
            Write-Host "$([char]0x276F)" -NoNewline
            Write-Host 'goto' -ForegroundColor Yellow -NoNewline
            Write-Host ' -Add ' -NoNewline -ForegroundColor DarkGray
            Write-Host "@{'" -NoNewline
            Write-Host 'NickName' -ForegroundColor Blue -NoNewline
            Write-Host "' = '" -NoNewline
            Write-Host 'FullPath' -NoNewline -ForegroundColor Blue
            Write-Host "'}${nl}"
            Write-Host "# For more Syntax Info run:${nl}" -ForegroundColor Green
            Write-Host "$([char]0x276F)" -NoNewline
            Write-Host 'get-help' -ForegroundColor Yellow -NoNewline
            Write-Host ' goto ' -NoNewline
            Write-Host "-detailed${nl}" -ForegroundColor DarkGray
          }
        }
      )
    )
  }

  process {
    # Create The '$go_locations' variable. Used by -Add parameters
    $go_locations = Update-LocationsDictionary $(Invoke-Command -ScriptBlock $Get_Locations) # This will also Update a $Locations variable, which is a pscustomobject (easy to play with)
    # List all available/registered locations
    if (-not $ListAvailable) {
      if ($PSCmdlet.ParameterSetName -eq "Path") {
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Path')) {
          if ("$Path" -ne "") {
            $Location = $Locations | Where-Object { $_.Path -eq $Path }
            Invoke-Command -ScriptBlock $set_Location -ArgumentList @($Location, $Path)
          } else {
            Invoke-Command -ScriptBlock $WriteHelp
          }
        } else {
          Write-Error "Please provide a path"
          Invoke-Command -ScriptBlock $WriteHelp
        }
      } elseif ($PSCmdlet.ParameterSetName -eq "Name") {
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Name')) {
          if ("$Name" -ne "") {
            $Location = $Locations | Where-Object { $_.Name -eq $Name }
            Invoke-Command -ScriptBlock $set_Location -ArgumentList @($Location, $Name)
          } else {
            Invoke-Command -ScriptBlock $WriteHelp
          }
        } else {
          Write-Error "Please provide a Name"
          Invoke-Command -ScriptBlock $WriteHelp
        }
      }
    } else {
      Write-Host $go_locations
    }
  }

  end {
    if ($CanUsetheJson) {
      Write-Verbose -Message "Update Locations Dictionary from Json"
      Update-LocationsDictionary $Locations
    } else {
      Write-Verbose -Message "Update Locations Dictionary Using defaults"
      Update-LocationsDictionary
    }
    $ErrorActionPreference = $oeap
  }
}

Function Invoke-PathShortener {
  <#
    .SYNOPSIS
        Path Shortener
    .EXAMPLE
        Invoke-PathShortener
        Will take the current path and shortened it using default values.
    .EXAMPLE
        Invoke-PathShortener -KeepBefore 3
        Will shorten the current path and keep the first 3 parts and last 1.
    .EXAMPLE
        Invoke-PathShortener -KeepBefore 3 -KeepAfter 2
        Will shorten the current path and keep the first 3 parts and the last 2 parts.
    .EXAMPLE
        'C:\Windows\System32\WindowsPowerShell\v1.0\Modules' | Invoke-PathShortener -TruncateChar ([char]8230)
        Will shorten the path piped in from the pipeline, using a custom truncate character.
    #>
  [CmdletBinding()]
  param (
    # Path to shorten.
    [Parameter(Position = 0, Mandatory = $false , ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullorEmpty()]
    [string]$Path = $ExecutionContext.SessionState.Path.CurrentLocation.Path,

    # Number of parts to keep before truncating. Default value is 2.
    [Parameter()]
    [ValidateRange(0, [int32]::MaxValue)]
    [int]$KeepBefore = 2,

    # Number of parts to keep after truncating. Default value is 1.
    [Parameter()]
    [ValidateRange(1, [int32]::MaxValue)]
    [int]$KeepAfter = 1,

    # Path separator character.
    [Parameter()]
    [string]$Separator = [System.IO.Path]::DirectorySeparatorChar,

    # Truncate character(s). Default is '...'
    # Use '[char]8230' to use the horizontal ellipsis character instead.
    [Parameter()]
    [string]$TruncateChar = [char]8230
  )
  process {
    $Path = (Resolve-Path -Path $Path).Path
    $splitPath = $Path.Split($Separator, [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($splitPath.Count -gt ($KeepBefore + $KeepAfter)) {
      $outPath = [string]::Empty
      for ($i = 0; $i -lt $KeepBefore; $i++) {
        $outPath += $splitPath[$i] + $Separator
      }
      $outPath += "$($TruncateChar)$($Separator)"
      for ($i = ($splitPath.Count - $KeepAfter); $i -lt $splitPath.Count; $i++) {
        if ($i -eq ($splitPath.Count - 1)) {
          $outPath += $splitPath[$i]
        } else {
          $outPath += $splitPath[$i] + $Separator
        }
      }
    } else {
      $outPath = $splitPath -join $Separator
      if ($splitPath.Count -eq 1) {
        $outPath += $Separator
      }
    }
  }
  End {
    return $outPath
  }
}

function Get-Dirtree {
  # .SYNOPSIS
  # 	Lists the full directory tree
  # .DESCRIPTION
  # 	This PowerShell script lists the full directory tree.
  [CmdletBinding()]
  param (
    [string]$DirTree = "$PWD"
  )

  begin {
    function ListDir {
      param([string]$Directory, [int]$Depth)
      $Depth++
      $Items = Get-ChildItem -Path $Directory
      foreach ($Item in $Items) {
        $Filename = $Item.Name
        if ($Item.Mode -like "d*") {
          for ($i = 0; $i -lt $Depth; $i++) {
            Write-Host -NoNewline "+--"
          }
          Write-Host -ForegroundColor green "📂$Filename"
          ListDir "$Directory\$Filename" $Depth
          $script:Dirs++
        } else {
          for ($i = 1; $i -lt $Depth; $i++) {
            Write-Host -NoNewline "|  "
          }
          Write-Host "|-$Filename ($($Item.Length) bytes)"
          $script:Files++
          $script:Bytes += $Item.Length
        }
      }
    }
  }

  process {
    try {
      [int]$script:Dirs = 1
      [int]$script:Files = 0
      [int]$script:Bytes = 0
      ListDir $DirTree 0
      Write-Host "($($script:Dirs) directories, $($script:Files) files, $($script:Bytes) bytes total)"
      # success
    } catch {
      # Write-Log $_.Exception.ErrorRecord
      Write-Verbose -Message "Errored: $($_.CategoryInfo.Category) : $($_.CategoryInfo.Reason) : $($_.Exception.Message)"
      break
    }
  }
}

function Get-FolderEntry {
  # .SYNOPSIS
  #     Lists all folders under a specified folder regardless of character limitation on path depth.

  # .DESCRIPTION
  #     Lists all folders under a specified folder regardless of character limitation on path depth.

  #     This is based on Boe's Get-FolderItem command here:  http://gallery.technet.microsoft.com/scriptcenter/Get-Deeply-Nested-Files-a2148fd7

  # .FUNCTIONALITY
  #     Computers

  # .PARAMETER Path
  #     One or more paths to search for subdirectories under

  # .PARAMETER ExcludeFolder
  #     One or more paths to exclude from query

  # .EXAMPLE
  #     Get-FolderEntry -Path "C:\users"

  #         FullPathLength FullName                                        FileCount
  #         -------------- --------                                        ---------
  #                      9 C:\Users\                                       1
  #                     23 C:\Users\SomeUser\                              7
  #                     31 C:\Users\SomeUser\AppData\                      0
  #                     37 C:\Users\SomeUser\AppData\Local\                0
  #                     47 C:\Users\SomeUser\AppData\Local\Microsoft\      0
  #                     ...

  #     Description
  #     -----------
  #     Returns all folders under the users folder.

  # .EXAMPLE
  #     Get-FolderEntry -Path "C:\users" -excludefolder "C:\Users\SomeUser\AppData\Local\Microsoft\"

  #         FullPathLength FullName                                                FileCount
  #         -------------- --------                                                ---------
  #                      9 C:\Users\                                               1
  #                     23 C:\Users\SomeUser\                                      7
  #                     31 C:\Users\SomeUser\AppData\                              0
  #                     37 C:\Users\SomeUser\AppData\Local\                        0
  #                     52 C:\Users\SomeUser\AppData\Local\Microsoft Help\         0          #NOTE that we skipped the excludefolder path
  #                     ...

  #     Description
  #     -----------
  #     Returns all folders under the users folder, excluding C:\Users\SomeUser\AppData\Local\Microsoft\ and all subdirectories

  # .INPUTS
  #     System.String

  # .OUTPUTS
  #     System.IO.RobocopyDirectoryInfo

  # .NOTES
  #     Name: Get-FolderItem
  #     Author: Boe Prox
  #     Date Created: 31 March 2013
  #     Updated by rcm
  [cmdletbinding(DefaultParameterSetName = 'Filter')]
  Param (
    [parameter(
      Position = 0,
      ValueFromPipeline = $True,
      ValueFromPipelineByPropertyName = $True)]
    [Alias('FullName')]
    [string[]]$Path = $PWD,

    [parameter(ParameterSetName = 'Filter')]
    [string[]]$Filter = '*.*',

    [parameter(ParameterSetName = 'Exclude')]
    [string[]]$ExcludeFolder
  )

  Begin {

    #Define arguments for robocopy and regex to parse results
    $array = @("/L", "/S", "/NJH", "/BYTES", "/FP", "/NC", "/NFL", "/TS", "/XJ", "/R:0", "/W:0")
    $regex = "^(?<Count>\d+)\s+(?<FullName>.*)"

    #Create an arraylist
    $params = New-Object System.Collections.Arraylist
    $params.AddRange($array)
  }

  Process {

    ForEach ($item in $Path) {
      Try {

        $item = (Resolve-Path -LiteralPath $item -ErrorAction Stop).ProviderPath

        If (-Not (Test-Path -LiteralPath $item -Type Container -ErrorAction Stop)) {
          Write-Warning ("{0} is not a directory and will be skipped" -f $item)
          Return
        }

        If ($PSBoundParameters['ExcludeFolder']) {
          $filterString = ($ExcludeFolder | ForEach-Object { "'$_'" }) -join ','
          $Script = "robocopy `"$item`" NULL $Filter $params /XD $filterString"
        } Else {
          $Script = "robocopy `"$item`" NULL $Filter $params"
        }

        Write-Verbose ("Scanning {0}" -f $item)

        #Run robocopy and parse results into an object.
        [scriptblock]::Create("$Script").Invoke() | ForEach-Object {
          Try {
            If ($_.Trim() -match $regex) {
              $object = New-Object PSObject -Property @{
                FullName       = $matches.FullName
                FileCount      = [int64]$matches.Count
                FullPathLength = [int] $matches.FullName.Length
              } | Select-Object FullName, FileCount, FullPathLength
              $object.pstypenames.insert(0, 'System.IO.RobocopyDirectoryInfo')
              Write-Output $object
            } Else {
              Write-Verbose ("Not matched: {0}" -f $_)
            }
          } Catch {
            Write-Warning ("{0}" -f $_.Exception.Message)
            Return
          }
        }
      } Catch {
        Write-Warning ("{0}" -f $_.Exception.Message)
        Return
      }
    }
  }
}

function Get-LibraryNames {
  <#
.SYNOPSIS
Lists all Windows Library folders (My Pictures, personal, downloads, etc)
    # New-Object -ComObject WScript.Shell
    # New-Object -ComObject WScript.Network
    # New-Object -ComObject Scripting.Dictionary
    # New-Object -ComObject Scripting.FileSystemObject
.DESCRIPTION
Libraries are special folders that map to a specific location on disk. These are usually found somewhere under $env:userprofile. This function can be used to discover the existing libraries and then use Move-LibraryDirectory to move the path of a library if desired.
#>
  $shells = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
  $retVal = @()
    (Get-Item $shells).Property | ForEach-Object {
    $property = ( Get-ItemProperty -Path $shells -Name $_ )
    $retVal += @{ "$_" = $property."$_" }
  }
  return $retVal
}

function Get-NTFSPermission {
  <#
.SYNOPSIS
    To get permission information on a specified Path or folder name
.DESCRIPTION
    To get permission information on a specified Path or folder name
.PARAMETER Path
    The name of the path
.EXAMPLE
    Get-NTFSPermission -Path "C:\Temp"

    Would return:

    A listing of all of the permissions
#>
  [CmdletBinding()]
  param([string[]] $Path)

  begin {
    Write-Host $MyInvocation
  }

  process {
    foreach ($curPath in $Path) {
      Write-Verbose "Path specified was [$($curPath)]"
      if (-not (Test-Path -Path $curPath)) {
        Write-Error -Message "Path [$($curPath)] does not exist"
        break
      } else {
        Write-Verbose "The path [$($curPath)] exists"
      }
      $acl = Get-Acl -Path $curPath
      $aclPermissions = $acl | Select-Object -ExpandProperty access
      $ComputerName = $env:COMPUTERNAME
      $returnVariable = @()
      $aclPermissions | ForEach-Object {
        $tmpObject = '' | Select-Object -Property ComputerName, Path, AccessType, IdentityReference, Rights, IsInherited, InheritanceFlags, PropogationFlags
        $tmpObject.ComputerName = $ComputerName
        $tmpObject.Path = $curPath
        $tmpObject.AccessType = $_.AccessControlType
        $tmpObject.IdentityReference = $_.IdentityReference
        $tmpObject.InheritanceFlags = $_.InheritanceFlags
        #        $tmpObject.Rights               = ConvertFrom-AccessMask -AccessMask $_.FileSystemRights.value__
        $tmpObject.Rights = ConvertFrom-FsRight -Rights (Convert-Int32ToUint32 -Number $_.FileSystemRights.value__)
        $tmpObject.PropogationFlags = $_.PropogationFlags
        $returnVariable += $tmpObject
      }
    }
  }

  end {
    Write-Output -InputObject $returnVariable
    Write-Verbose -Message "Complete."
  }
}



function Get-RecycleBin {
  # .SYNOPSIS
  # Lists the content of the recycle bin folder
  [CmdletBinding()]
  param (
  )

  process {
    try {
      $res = $(New-Object -ComObject Shell.Application).NameSpace(0x0a).Items() | Select-Object Name, Size, Path
      # success
      return $res
    } catch {
      $PSCmdlet.ThrowTerminatingError($_)
      # Write-Log $_.Exception.ErrorRecord
      # Write-Verbose -Message "Errored: $($_.CategoryInfo.Category) : $($_.CategoryInfo.Reason) : $($_.Exception.Message)"
      break
    }
  }
}

function Get-SpecialFolder {
  # .SYNOPSIS
  #     Gets special folder name location
  # .DESCRIPTION
  #     Gets special folder name location. Function aliased to 'Show-SpecialFolder' for
  #     backward compatibility.
  # .PARAMETER Name
  #     The name of the special folder
  # .PARAMETER IncludeInput
  #     Switch to include the input in the output
  # .EXAMPLE
  #     Get-SpecialFolder -Name CommonDocuments -IncludeInput

  #     Would return
  #     SpecialFolder   Path
  #     -------------   ----
  #     CommonDocuments C:\Users\Public\Documents
  # .EXAMPLE
  #     Get-SpecialFolder -Name MyDocuments -IncludeInput

  #     Would return the following if logged in as 'SampleUser'
  #     SpecialFolder Path
  #     ------------- ----
  #     MyDocuments   C:\Users\SampleUser\Documents
  [CmdletBinding(ConfirmImpact = 'None')]
  [alias('Show-SpecialFolder')]
  Param (
    [ValidateSet( 'AdminTools', 'ApplicationData', 'CDBurning',
      'CommonAdminTools', 'CommonApplicationData', 'CommonDesktopDirectory',
      'CommonDocuments', 'CommonMusic', 'CommonOemLinks', 'CommonPictures',
      'CommonProgramFiles', 'CommonProgramFilesX86', 'CommonPrograms',
      'CommonStartMenu', 'CommonStartup', 'CommonTemplates', 'CommonVideos',
      'Cookies', 'Desktop', 'DesktopDirectory', 'Favorites', 'Fonts', 'History',
      'InternetCache', 'LocalApplicationData', 'LocalizedResources', 'MyComputer',
      'MyDocuments', 'MyMusic', 'MyPictures', 'MyVideos', 'NetworkShortcuts',
      'Personal', 'PrinterShortcuts', 'ProgramFiles', 'ProgramFilesX86', 'Programs',
      'Recent', 'Resources', 'SendTo', 'StartMenu', 'Startup', 'System', 'SystemX86',
      'Templates', 'UserProfile', 'Windows' )]
    [string] $Name,

    [switch] $IncludeInput
  )

  begin {
    Write-Host $MyInvocation
  }

  process {
    if ($Name) {
      $SpecialFolders = [System.Enum]::GetNames([System.Environment+SpecialFolder]) | Where-Object { $_ -eq $Name }
    } else {
      $SpecialFolders = [System.Enum]::GetNames([System.Environment+SpecialFolder]) | Sort-Object
    }
    foreach ($curSpecial in $SpecialFolders) {
      if (-not $IncludeInput) {
        Write-Output -InputObject ([Environment]::GetFolderPath($curSpecial))
      } else {
        New-Object -TypeName psobject -Property ([ordered] @{
            SpecialFolder = $curSpecial
            Path          = [Environment]::GetFolderPath($curSpecial)
          })
      }
    }
  }

  end {
    Write-Verbose -Message "Complete."
  }
}


function Remove-EmptyDirectories {
  # .SYNOPSIS
  # 	Removes all empty subfolders within a directory tree
  # .DESCRIPTION
  # 	This PowerShell script removes all empty subfolders within a directory tree.
  # .PARAMETER DirTree
  # 	Specifies the path to the directory tree
  # .EXAMPLE
  # 	PS> Remove-EmptyDirectories C:\Temp
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([string]$DirTree = "")

  try {
    if ($DirTree -eq "" ) { $DirTree = Read-Host "Enter the path to the directory tree" }

    $Folders = @()
    foreach ($Folder in (Get-ChildItem -Path "$DirTree" -Recurse | Where-Object { $_.PSisContainer })) {
      $Folders += New-Object PSObject -Property @{
        Object = $Folder
        Depth  = ($Folder.FullName.Split("\")).Count
      }
    }
    $Folders = $Folders | Sort-Object Depth -Descending

    $Deleted = @()
    foreach ($Folder in $Folders) {
      if ($Folder.Object.GetFileSystemInfos().Count -eq 0) {
        $Deleted += [PSCustomObject]@{
          Folder       = $Folder.Object.FullName
          Deleted      = (Get-Date -Format "hh:mm:ss tt")
          Created      = $Folder.Object.CreationTime
          LastModified = $Folder.Object.LastWriteTime
          Owner        = (Get-Acl $Folder.Object.FullName).Owner
        }
        Remove-Item -Path $Folder.Object.FullName -Force
      }
    }
    Write-Host "✅  Done."
  } catch {
    # Write-Log $_.Exception.ErrorRecord
    Write-Verbose -Message "Errored: $($_.CategoryInfo.Category) : $($_.CategoryInfo.Reason) : $($_.Exception.Message)"
  }
}






function Sync-Directory {
  # .Synopsis
  # 	Syncs two directories with some interaction.
  # 	Author: Roman Kuzmin

  # .Description
  # 	Requires:
  # 		Robocopy.exe, Windows utility since Windows Vista
  # 		PowerShell host supporting Write-Host with colors
  # 	Optional:
  # 		%MERGE%, directory comparison application

  # 	The script automates one simple scenario. Some directory exists in several
  # 	places (home, work, removable drive, backup copy, etc.) but changes in it
  # 	are normally done in one of them and they should be propagated to another.
  # 	The script visualizes these changes and tries to determine which directory
  # 	is newer and should be mirrored.

  # 	It is possible to skip the suggested operation and tell to mirror in the
  # 	opposite direction or start an external directory comparison application.

  # 	The tool is simple but it saves time when such operations are repeatedly
  # 	performed manually. Besides it may help to avoids mistakes and data loss
  # 	(like copying in a wrong direction).

  # .Parameter Directory1
  # 		Specifies the first directory.
  # 		If it is missing then the second should exist.
  # .Parameter Directory2
  # 		Specifies the second directory.
  # 		If it is missing then the first should exist.
  # .Parameter Arguments
  # 		Additional Robocopy arguments. Example:
  # 		... -Arguments /XD, bin, obj, /XF, *.tmp, *.bak

  # .Example
  # 	>
  # 	Lets $env:pc_master and $env:pc_slave are names of two machines. Then this
  # 	code syncs the current directory on the current machine and the directory
  # 	with the same path on another machine:

  # 	$that = if ($env:COMPUTERNAME -eq $env:pc_master) {$env:pc_slave} else {$env:pc_master}
  # 	$dir1 = "$pwd"
  # 	$dir2 = "\\$that\$($dir1 -replace '^(.):', '$1$')"
  # 	Sync-Directory $dir1 $dir2

  # .Link
  # 	https://github.com/nightroman/PowerShelf
  [CmdletBinding()]
  param(
    [Parameter(Position = 1, Mandatory = 1)]
    [string]$Directory1,
    [Parameter(Position = 2, Mandatory = 1)]
    [string]$Directory2,
    [string[]]$Arguments
  )

  begin {
    function Invoke-Robocopy($source, $target) {
      $param = $source, $target, '/MIR', '/FFT', '/NDL', '/NP', '/NS'
      if ($Arguments) { $param += $Arguments }
      Robocopy.exe $param
      if ($LastExitCode -gt 3) { throw 'Robocopy failed.' }
    }

    # asks for a choice
    function Get-Choice {
      [CmdletBinding()]
      param (
        [Parameter()]
        [string]$Caption = 'Confirm',

        [Parameter()]
        [string]$Message = 'Are you sure you want to continue?',

        [Parameter()]
        [string[]]$Choices = ('&Yes', 'Continue', '&No', 'Skip this'),

        [Parameter()]
        [int]$DefaultChoice = 0
      )
      $descriptions = @()
      for ($i = 0; $i -lt $Choices.Count; $i += 2) {
        $c = [System.Management.Automation.Host.ChoiceDescription]$Choices[$i]
        $c.HelpMessage = $Choices[$i + 1]
        $descriptions += $c
      }
      $Host.UI.PromptForChoice($Caption, $Message, [System.Management.Automation.Host.ChoiceDescription[]]$descriptions, $DefaultChoice)
    }
  }

  process {
    trap { $PSCmdlet.ThrowTerminatingError($_) }
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $Directory1 = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Directory1)
    $Directory2 = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Directory2)
    Write-Host "Directory1: $Directory1"
    Write-Host "Directory2: $Directory2"

    $exist1 = [System.IO.Directory]::Exists($Directory1)
    $exist2 = [System.IO.Directory]::Exists($Directory2)

    if (!$exist1 -and !$exist2) {
      throw "Directories '$Directory1' and '$Directory2' do not exist."
    }

    # no source?
    if (!$exist1) {
      Write-Warning "Directory1 '$Directory1' does not exist."
      if ((Get-Choice "Mirror 2->1 '$Directory2' to '$Directory1'") -eq 0) {
        Invoke-Robocopy $Directory2 $Directory1
      }
      return
    }

    # no target?
    if (!$exist2) {
      Write-Warning "Directory2 '$Directory2' does not exist."
      if ((Get-Choice "Mirror 1->2 '$Directory1' to '$Directory2'") -eq 0) {
        Invoke-Robocopy $Directory1 $Directory2
      }
      return
    }

    function Write-Info($Info, $Color) {
      Write-Host $Info -ForegroundColor $Color
    }

    ### get file info
    $newer1, $newer2, $extra1, $extra2, $others = 0
    $param = $Directory1, $Directory2, '/L', '/MIR', '/FFT', '/NDL', '/NP', '/NS', '/NJH', '/NJS'
    if ($Arguments) { $param += $Arguments }
    switch -regex (Robocopy.exe $param) {
      '^\s+Newer' {
        Write-Host $_ Green
        ++$newer1
        continue
      }
      '^\s+Older' {
        Write-Host $_ Cyan
        ++$newer2
        continue
      }
      '^\s+New file' {
        Write-Host $_ DarkGreen
        ++$extra1
        continue
      }
      '^\s+\*EXTRA File' {
        Write-Host $_ DarkCyan
        ++$extra2
        continue
      }
      '^\s*$|^\s*\*EXTRA Dir' {
        continue
      }
      default {
        Write-Host $_ Yellow
        ++$others
      }
    }
    if ($LastExitCode -gt 3) { throw 'Robocopy failed.' }

    # no job?
    if ($newer1 + $newer2 + $extra1 + $extra2 + $others -eq 0) {
      Write-Host 'Directories are synchronized.'
      return
    }

    # summary
    Write-Host ''
    if ($newer1) { Write-Host "$newer1 newer in '$Directory1'" -ForegroundColor Green }
    if ($newer2) { Write-Host "$newer2 newer in '$Directory2'" -ForegroundColor Cyan }
    if ($extra1) { Write-Host "$extra1 extra in '$Directory1'" -ForegroundColor DarkGreen }
    if ($extra2) { Write-Host "$extra2 extra in '$Directory2'" -ForegroundColor DarkCyan }

    # warnings
    if ($others) { Write-Warning "$others mismatched" }
    if ($newer1 -and $newer2) { Write-Warning "Both directories have newer files." }

    # ask 1->2
    if (!$others -and $newer1 -and !$newer2) {
      if ((Get-Choice "Mirror 1->2 '$Directory1' to '$Directory2'") -eq 0) {
        Invoke-Robocopy $Directory1 $Directory2
        return
      }
    }

    # ask 2->1
    if (!$others -and !$newer1 -and $newer2) {
      if ((Get-Choice "Mirror 2->1 '$Directory2' to '$Directory1'") -eq 0) {
        Invoke-Robocopy $Directory2 $Directory1
        return
      }
    }

    # more choices
    $choice = Get-Choice -Caption Choose -Message 'What would you like to do?' -Choices @(
      'Skip', '',
      '&1->2', "Mirror '$Directory1' to '$Directory2'",
      '&2->1', "Mirror '$Directory2' to '$Directory1'",
      '&Merge', "Start %MERGE%"
    )
    switch ($choice) {
      1 {
        Invoke-Robocopy $Directory1 $Directory2
      }
      2 {
        Invoke-Robocopy $Directory2 $Directory1
      }
      3 {
        if ($env:MERGE -and (Test-Path -LiteralPath $env:MERGE)) {
          Start-Process $env:MERGE "`"$Directory1`" `"$Directory2`""
        } else {
          Write-Warning "%MERGE% is not defined or does not exist."
        }
      }
    }
  }
}

function Test-PathNotInSettings($Path) {
  # .SYNOPSIS
  #    Validation of Path
  # .DESCRIPTION
  #    Validates that the parameter being validated:
  #    - is not null
  #    - is a folder and exists
  #    - and that it does not exist in settings where settings is:
  #      => the process PATH for Linux/OSX
  #      => the registry PATHs for Windows
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw 'Argument is null'
  }

  # Remove ending DirectorySeparatorChar for comparison purposes
  $Path = [Environment]::ExpandEnvironmentVariables($Path.TrimEnd([IO.Path]::DirectorySeparatorChar));

  if (![IO.Directory]::Exists($Path)) {
    throw "Path does not exist: $Path"
  }

  # [Environment]::GetEnvironmentVariable automatically expands all variables
  $InstalledPaths = @()
  if ([Environment]::OSVersion.Platform -eq "Win32NT") {
    $InstalledPaths += @(([Environment]::GetEnvironmentVariable('PATH', [EnvironmentVariableTarget]::User)) -split ([IO.Path]::PathSeparator))
    $InstalledPaths += @(([Environment]::GetEnvironmentVariable('PATH', [EnvironmentVariableTarget]::Machine)) -split ([IO.Path]::PathSeparator))
  } else {
    $InstalledPaths += @(([Environment]::GetEnvironmentVariable('PATH'), [EnvironmentVariableTarget]::Process) -split ([IO.Path]::PathSeparator))
  }

  # Remove ending DirectorySeparatorChar in all items of array for comparison purposes
  $InstalledPaths = $InstalledPaths | ForEach-Object { $_.TrimEnd([IO.Path]::DirectorySeparatorChar) }

  # if $InstalledPaths is in setting return false
  if ($InstalledPaths -icontains $Path) {
    throw 'Already in PATH environment variable'
  }
  return $true
}


function Set-KnownFolderPath {
  # .SYNOPSIS
  #     Sets a known folder's path using SHSetKnownFolderPath.
  # .EXAMPLE
  #     Set-KnownFolderPath -KnownFolder 'Desktop' -Path 'C:\'
  [CmdletBinding(SupportsShouldProcess)]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateSet('3DObjects', 'AddNewPrograms', 'AdminTools', 'AppUpdates', 'CDBurning', 'ChangeRemovePrograms', 'CommonAdminTools', 'CommonOEMLinks', 'CommonPrograms', 'CommonStartMenu', 'CommonStartup', 'CommonTemplates', 'ComputerFolder', 'ConflictFolder', 'ConnectionsFolder', 'Contacts', 'ControlPanelFolder', 'Cookies', 'Desktop', 'Documents', 'Downloads', 'Favorites', 'Fonts', 'Games', 'GameTasks', 'History', 'InternetCache', 'InternetFolder', 'Links', 'LocalAppData', 'LocalAppDataLow', 'LocalizedResourcesDir', 'Music', 'NetHood', 'NetworkFolder', 'OriginalImages', 'PhotoAlbums', 'Pictures', 'Playlists', 'PrintersFolder', 'PrintHood', 'Profile', 'ProgramData', 'ProgramFiles', 'ProgramFilesX64', 'ProgramFilesX86', 'ProgramFilesCommon', 'ProgramFilesCommonX64', 'ProgramFilesCommonX86', 'Programs', 'Public', 'PublicDesktop', 'PublicDocuments', 'PublicDownloads', 'PublicGameTasks', 'PublicMusic', 'PublicPictures', 'PublicVideos', 'QuickLaunch', 'Recent', 'RecycleBinFolder', 'ResourceDir', 'RoamingAppData', 'SampleMusic', 'SamplePictures', 'SamplePlaylists', 'SampleVideos', 'SavedGames', 'SavedSearches', 'SEARCH_CSC', 'SEARCH_MAPI', 'SearchHome', 'SendTo', 'SidebarDefaultParts', 'SidebarParts', 'StartMenu', 'Startup', 'SyncManagerFolder', 'SyncResultsFolder', 'SyncSetupFolder', 'System', 'SystemX86', 'Templates', 'TreeProperties', 'UserProfiles', 'UsersFiles', 'Videos', 'Windows')]
    [string]$KnownFolder,
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  begin {
    # Reads Data from DefaultFolderLocations.json
    # TODO: Add json parse blocks here .
    $ogeap = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
    # Get Known Folders
    #-------------------
    $ShellFoldersPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    try {
      Get-ItemProperty -Path $ShellFoldersPath -ErrorAction Stop
      [bool]$GoodToGo = $?
    } catch [System.Management.Automation.ItemNotFoundException] {
      # Registry Key itself is missing ie: Path Does not Exist //
      if (Test-Path $ShellFoldersPath) {
        [bool]$GoodToGo = $true
      } else {
        $PSCmdlet.WriteWarning("$ShellFoldersPath does not exist!")
        New-Item -Path $ShellFoldersPath -Force -WhatIf | Out-Null
        $PSCmdlet.WriteInformation("Created RegistryPath: $ShellFoldersPath")
        [bool]$GoodToGo = $false
      }
    }
    if (-not $GoodToGo) {
      $PSCmdlet.WriteWarning("ShellFolders RegistryPath does not exist, or is empty. `nExiting now ..")
      return
    }
    # --------------------
    # loop trough each prop
    foreach ($item in $(Get-ItemProperty -Path $ShellFoldersPath)) {
      #EX: $property = 'Personalss'
      $property = "$item"
      try {
        Get-ItemProperty -Path $ShellFoldersPath -Name $property
      } catch [System.Management.Automation.PSArgumentException] {
        "[Error] Registry KeyProperty named '$property' is missing" | Write-Error
      }
    }
    $ErrorActionPreference = $ogeap
    # ----------------------
    # Now set the value
    # New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType REG_SZ -Force


    # known folder GUIDs
    $KnownFolders = @{
      '3DObjects'             = '31C0DD25-9439-4F12-BF41-7FF4EDA38722';
      'AddNewPrograms'        = 'de61d971-5ebc-4f02-a3a9-6c82895e5c04';
      'AdminTools'            = '724EF170-A42D-4FEF-9F26-B60E846FBA4F';
      'AppUpdates'            = 'a305ce99-f527-492b-8b1a-7e76fa98d6e4';
      'CDBurning'             = '9E52AB10-F80D-49DF-ACB8-4330F5687855';
      'ChangeRemovePrograms'  = 'df7266ac-9274-4867-8d55-3bd661de872d';
      'CommonAdminTools'      = 'D0384E7D-BAC3-4797-8F14-CBA229B392B5';
      'CommonOEMLinks'        = 'C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D';
      'CommonPrograms'        = '0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8';
      'CommonStartMenu'       = 'A4115719-D62E-491D-AA7C-E74B8BE3B067';
      'CommonStartup'         = '82A5EA35-D9CD-47C5-9629-E15D2F714E6E';
      'CommonTemplates'       = 'B94237E7-57AC-4347-9151-B08C6C32D1F7';
      'ComputerFolder'        = '0AC0837C-BBF8-452A-850D-79D08E667CA7';
      'ConflictFolder'        = '4bfefb45-347d-4006-a5be-ac0cb0567192';
      'ConnectionsFolder'     = '6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD';
      'Contacts'              = '56784854-C6CB-462b-8169-88E350ACB882';
      'ControlPanelFolder'    = '82A74AEB-AEB4-465C-A014-D097EE346D63';
      'Cookies'               = '2B0F765D-C0E9-4171-908E-08A611B84FF6';
      'Desktop'               = 'B4BFCC3A-DB2C-424C-B029-7FE99A87C641';
      'Documents'             = 'FDD39AD0-238F-46AF-ADB4-6C85480369C7';
      'Downloads'             = '374DE290-123F-4565-9164-39C4925E467B';
      'Favorites'             = '1777F761-68AD-4D8A-87BD-30B759FA33DD';
      'Fonts'                 = 'FD228CB7-AE11-4AE3-864C-16F3910AB8FE';
      'Games'                 = 'CAC52C1A-B53D-4edc-92D7-6B2E8AC19434';
      'GameTasks'             = '054FAE61-4DD8-4787-80B6-090220C4B700';
      'History'               = 'D9DC8A3B-B784-432E-A781-5A1130A75963';
      'InternetCache'         = '352481E8-33BE-4251-BA85-6007CAEDCF9D';
      'InternetFolder'        = '4D9F7874-4E0C-4904-967B-40B0D20C3E4B';
      'Links'                 = 'bfb9d5e0-c6a9-404c-b2b2-ae6db6af4968';
      'LocalAppData'          = 'F1B32785-6FBA-4FCF-9D55-7B8E7F157091';
      'LocalAppDataLow'       = 'A520A1A4-1780-4FF6-BD18-167343C5AF16';
      'LocalizedResourcesDir' = '2A00375E-224C-49DE-B8D1-440DF7EF3DDC';
      'Music'                 = '4BD8D571-6D19-48D3-BE97-422220080E43';
      'NetHood'               = 'C5ABBF53-E17F-4121-8900-86626FC2C973';
      'NetworkFolder'         = 'D20BEEC4-5CA8-4905-AE3B-BF251EA09B53';
      'OriginalImages'        = '2C36C0AA-5812-4b87-BFD0-4CD0DFB19B39';
      'PhotoAlbums'           = '69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C';
      'Pictures'              = '33E28130-4E1E-4676-835A-98395C3BC3BB';
      'Playlists'             = 'DE92C1C7-837F-4F69-A3BB-86E631204A23';
      'PrintersFolder'        = '76FC4E2D-D6AD-4519-A663-37BD56068185';
      'PrintHood'             = '9274BD8D-CFD1-41C3-B35E-B13F55A758F4';
      'Profile'               = '5E6C858F-0E22-4760-9AFE-EA3317B67173';
      'ProgramData'           = '62AB5D82-FDC1-4DC3-A9DD-070D1D495D97';
      'ProgramFiles'          = '905e63b6-c1bf-494e-b29c-65b732d3d21a';
      'ProgramFilesX64'       = '6D809377-6AF0-444b-8957-A3773F02200E';
      'ProgramFilesX86'       = '7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E';
      'ProgramFilesCommon'    = 'F7F1ED05-9F6D-47A2-AAAE-29D317C6F066';
      'ProgramFilesCommonX64' = '6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D';
      'ProgramFilesCommonX86' = 'DE974D24-D9C6-4D3E-BF91-F4455120B917';
      'Programs'              = 'A77F5D77-2E2B-44C3-A6A2-ABA601054A51';
      'Public'                = 'DFDF76A2-C82A-4D63-906A-5644AC457385';
      'PublicDesktop'         = 'C4AA340D-F20F-4863-AFEF-F87EF2E6BA25';
      'PublicDocuments'       = 'ED4824AF-DCE4-45A8-81E2-FC7965083634';
      'PublicDownloads'       = '3D644C9B-1FB8-4f30-9B45-F670235F79C0';
      'PublicGameTasks'       = 'DEBF2536-E1A8-4c59-B6A2-414586476AEA';
      'PublicMusic'           = '3214FAB5-9757-4298-BB61-92A9DEAA44FF';
      'PublicPictures'        = 'B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5';
      'PublicVideos'          = '2400183A-6185-49FB-A2D8-4A392A602BA3';
      'QuickLaunch'           = '52a4f021-7b75-48a9-9f6b-4b87a210bc8f';
      'Recent'                = 'AE50C081-EBD2-438A-8655-8A092E34987A';
      'RecycleBinFolder'      = 'B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC';
      'ResourceDir'           = '8AD10C31-2ADB-4296-A8F7-E4701232C972';
      'RoamingAppData'        = '3EB685DB-65F9-4CF6-A03A-E3EF65729F3D';
      'SampleMusic'           = 'B250C668-F57D-4EE1-A63C-290EE7D1AA1F';
      'SamplePictures'        = 'C4900540-2379-4C75-844B-64E6FAF8716B';
      'SamplePlaylists'       = '15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5';
      'SampleVideos'          = '859EAD94-2E85-48AD-A71A-0969CB56A6CD';
      'SavedGames'            = '4C5C32FF-BB9D-43b0-B5B4-2D72E54EAAA4';
      'SavedSearches'         = '7d1d3a04-debb-4115-95cf-2f29da2920da';
      'SEARCH_CSC'            = 'ee32e446-31ca-4aba-814f-a5ebd2fd6d5e';
      'SEARCH_MAPI'           = '98ec0e18-2098-4d44-8644-66979315a281';
      'SearchHome'            = '190337d1-b8ca-4121-a639-6d472d16972a';
      'SendTo'                = '8983036C-27C0-404B-8F08-102D10DCFD74';
      'SidebarDefaultParts'   = '7B396E54-9EC5-4300-BE0A-2482EBAE1A26';
      'SidebarParts'          = 'A75D362E-50FC-4fb7-AC2C-A8BEAA314493';
      'StartMenu'             = '625B53C3-AB48-4EC1-BA1F-A1EF4146FC19';
      'Startup'               = 'B97D20BB-F46A-4C97-BA10-5E3608430854';
      'SyncManagerFolder'     = '43668BF8-C14E-49B2-97C9-747784D784B7';
      'SyncResultsFolder'     = '289a9a43-be44-4057-a41b-587a76d7e7f9';
      'SyncSetupFolder'       = '0F214138-B1D3-4a90-BBA9-27CBC0C5389A';
      'System'                = '1AC14E77-02E7-4E5D-B744-2EB1AE5198B7';
      'SystemX86'             = 'D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27';
      'Templates'             = 'A63293E8-664E-48DB-A079-DF759E0509F7';
      'TreeProperties'        = '5b3749ad-b49f-49c1-83eb-15370fbd4882';
      'UserProfiles'          = '0762D272-C50A-4BB0-A382-697DCD729B80';
      'UsersFiles'            = 'f3ce0f7c-4901-4acc-8648-d5d44b04ef8f';
      'Videos'                = '18989B1D-99B5-455B-841C-AB7C74E4DDFC';
      'Windows'               = 'F38BF404-1D43-42F2-9305-67DE0B28FC23';
    }
  }

  process {
    # TODO: Add a knownfolder installer.scriptblock. (better if using some .Net API magic stuff.)
    # Define SHSetKnownFolderPath if it hasn't been defined already
    $Type = ([System.Management.Automation.PSTypeName]'KnownFolders').Type
    Try {
      $null = [SHSetKnownFolderPath]
    } Catch {
      # -not $Type -or $null -eq $Type
      $Type = Add-Type -Name 'KnownFolders' -Namespace 'SHSetKnownFolderPath' -Language CSharp -TypeDefinition "`n[DllImport(`"shell32.dll`")]`npublic static int SHSetKnownFolderPath(ref Guid folderId, uint flags, IntPtr token, [MarshalAs(UnmanagedType.LPWStr)] string path);`n";
    }
    # Validate the path
    if (Test-Path $Path -PathType Container) {
      # Call SHSetKnownFolderPath
      return $Type::SHSetKnownFolderPath([ref]$KnownFolders[$KnownFolder], 0, 0, $Path)
    } else {
      throw $(New-Object System.IO.DirectoryNotFoundException "Could not find part of the path $Path.")
    }
  }

  end {
    Write-Verbose -Message "✅ Done."
  }
}

function Move-ToRecycleBin {
  # .SYNOPSIS
  #     Instead of outright deleting a file, why not move it to the Recycle Bin?
  # .DESCRIPTION
  #     Instead of outright deleting a file, why not move it to the Recycle Bin?
  #     Function aliased to 'Recycle'
  # .PARAMETER Path
  #     A string or array of strings representing a file or a folder. Wildcards are
  #     acceptable and will be resolved to specific file or folder names. Can accept
  #     values from the pipeline.
  # .EXAMPLE
  #     Move-ToRecycleBin -Path c:\temp\dummyfile.txt -Verbose

  #     VERBOSE: Moving 'c:\temp\dummyfile.txt' to the Recycle Bin
  # .EXAMPLE
  #     Move-ToRecycleBin -Path c:\temp\dummyfile2.txt

  #     Would move c:\temp\dummyfile2.txt to the Recycle Bin
  # .EXAMPLE
  #     Move-ToRecycleBin .\FileDoesNotExist

  #     Move-ToRecycleBin : ERROR: Path [.\FileDoesNotExist] does not exist
  # .EXAMPLE
  #     Move-ToRecycleBin -Path 'File1.txt', 'File2.txt'

  #     Would move both File1.txt and File2.txt to the Recycle Bin
  [CmdletBinding(ConfirmImpact = 'Medium')]
  [alias('Recycle')]
  param (
    [Parameter(Mandatory, HelpMessage = 'Please enter a path to a file or folder. Wildcards accepted.', ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [string[]] $Path
  )

  begin {
    $FileSystem = [Microsoft.VisualBasic.FileIO.FileSystem]::New()
    Write-Host $MyInvocation
  }

  process {
    foreach ($currentPath in $Path) {
      if (Test-Path -Path $currentPath) {
        $File = Resolve-Path -Path $currentPath
        foreach ($currentFile in $File) {
          Write-Verbose ("Moving '{0}' to the Recycle Bin" -f $currentFile)
          if (Test-Path -Path $currentFile -PathType Container) {
            $FileSystem::DeleteDirectory($currentFile, 'OnlyErrorDialogs', 'SendToRecycleBin')
          } else {
            $FileSystem::DeleteFile($currentFile, 'OnlyErrorDialogs', 'SendToRecycleBin')
          }
        }
      } else {
        Write-Error -Message "ERROR: Path [$currentPath] does not exist"
      }
    }
  }

  end {
    Remove-Variable -Name FileSystem
    Write-Verbose -Message "Complete."
  }
}
