#!/usr/bin/env pwsh
using namespace System.IO
using namespace System.Collections.generic
using namespace System.Runtime.InteropServices
using module Private/cliHelper.filesystem.ftp
using module Private/cliHelper.filesystem.files
using module Private/cliHelper.filesystem.drives
using module Private/cliHelper.filesystem.rights
using module Private/cliHelper.filesystem.attrib
using module Private/cliHelper.filesystem.folders
using module Private/cliHelper.filesystem.claudeapi
using module Private/cliHelper.filesystem.shortcuts

enum TimeInterval {
  Years
  Months
  Days
  Hours
  Minutes
}
#region    Classes
# This code will organize the files in a directory into groups based on their date, and then create a folder for each group in the destinationDirectory.
# Each file in the group will be moved to its corresponding folder, according to the date of the file.

#.SYNOPSIS
# Uses AI to understand and organize files intuitively
class FsOrganizer : LLMagent {
  static [hashtable] $_Files
  FsOrganizer() {}
  static [void] Organize([string]$Directory) {
    [FsOrganizer]::Organize($Directory, "Organize files in my downloads path by file use case.")
  }
  static [PSCustomObject[]] Organize([string]$Directory, [string]$intent) {
    $r = @(); $f = [FsOrganizer]::GetFilesHt($Directory); $l = $Directory.Length
    $o = "@{`n{0}`n}" -f [FsOrganizer]::GetLLMresponse([FsOrganizer]::GetFolderAnalysisPrompt("$Directory", $intent))
    foreach ($key in $f.Keys) {
      $Path = [IO.Path]::Combine($Directory, $f[$key].N)
      $Dest = [IO.Path]::Combine($Directory, $o.Keys.Where({ $o.$_ -contains $key }), $f[$key].N)
      $r += [PSCustomObject]@{
        Path = $Path.Substring($l)
        Dest = $Dest.Substring($l)
      }
      Move-Item -Path $Path -Destination $Dest -WhatIf -Force
    }
    return $r
  }
  # Method to analyze folder and generate AI-suggested categories
  static [hashtable] GetFileMappingsKeys([string]$folderPath, [string]$intent) {
    $prompt = [FsOrganizer]::GetFolderAnalysisPrompt($folderPath, $intent)
    # For now, we'll return a default mapping if API call isn't implemented
    try {
      $response = Invoke-ClaudeAPI -Prompt $prompt
      # Convert ClaudeResponseToHashtable
      # Temporary default return until API is implemented
      $suggestedMappings = [FsOrganizer]::FileMappings
      Write-Verbose "AI analysis complete. Categories generated based on folder content. $response"
      return $suggestedMappings
    } catch {
      throw "Failed to generate FileMappings: $_"
    }
  }
  # Method to validate and normalize AI-suggested mappings
  static [hashtable] ValidateAIMappings([hashtable]$aiMappings) {
    $normalizedMappings = @{}
    foreach ($category in $aiMappings.Keys) {
      # Ensure extensions start with dot and are lowercase
      $normalizedExtensions = $aiMappings[$category] | ForEach-Object {
        $ext = $_.ToLower()
        if (!$ext.StartsWith('.')) {
          $ext = ".$ext"
        }
        $ext
      }
      # Remove any duplicates
      $normalizedExtensions = $normalizedExtensions | Select-Object -Unique
      # Add to normalized mappings
      $normalizedMappings[$category] = $normalizedExtensions
    }
    return $normalizedMappings
  }
  # Method to get file mappings based on AI suggestions
  static [void] UpdateMappingsFromAI([string]$folderPath, [string]$intent) {
    $aiMappings = [FsOrganizer]::GetFileMappingsKeys($folderPath, $intent)
    $validatedMappings = [FsOrganizer]::ValidateAIMappings($aiMappings)
    [FsOrganizer]::FileMappings = $validatedMappings
  }
  static [DirectoryInfo[]] GetDirectories([string]$Path) {
    return [FsOrganizer]::GetDirectories($Path, $false)
  }
  static [DirectoryInfo[]] GetDirectories([string]$Path, [bool]$Recurse) {
    return [FsOrganizer]::GetDirectories([FsOrganizer]::GetUnResolvedPath($Path), $Recurse, $false)
  }
  static [DirectoryInfo[]] GetDirectories([string]$Path, [bool]$Recurse, [bool]$IncludeHidden) {
    # .EXAMPLE
    # [FsOrganizer]::GetDirectories($pwd, $false)
    [string]$path = [FsOrganizer]::GetResolvedPath($Path)
    $ErrorActionPreference = "Stop"; $result = @()
    try {
      $di = [DirectoryInfo]::new($path)
      $enumOpt = [IO.EnumerationOptions]::new()
      $enumOpt.RecurseSubdirectories = $Recurse
      if ($IncludeHidden) { $enumOpt.AttributesToSkip -= 2 }
      $result += $di.GetDirectories("*", $enumOpt)
    } Catch {
      throw $_.exception
    }
    return $result
  }
  static [SFileInfo[]] GetFiles([string]$Path) {
    return [FsOrganizer]::GetFiles($Path, $false)
  }
  static [SFileInfo[]] GetFiles([string]$Path, [bool]$Recurse) {
    $r = @(); $i = 0; (Get-ChildItem -Path $Path -File -Recurse:$Recurse).ForEach({ $r += [SFileInfo]::New($_, $i); $i++ })
    return $r
  }
  static [Hashtable] GetFilesHt([string]$Path) {
    return [FsOrganizer]::GetFilesHt($Path, $false)
  }
  static [Hashtable] GetFilesHt([string]$Path, [bool]$Recurse) {
    $t = @{}; $i = 0; (Get-ChildItem -Path $Path -File -Recurse:$Recurse).ForEach({ [void]$t.Add($i, [SFileInfo]::New($_, $i)); $i++ })
    return $t
  }
  static [FileExtensionInfo[]] GetFileExtensionInfo([string[]]$Paths) {
    return [FsOrganizer]::GetFileExtensionInfo($Paths, $false, $false)
  }
  static [FileExtensionInfo[]] GetFileExtensionInfo([string[]]$Paths, [bool]$Recurse, [bool]$IncludeHidden) {
    $result = @(); $enumOpt = [IO.EnumerationOptions]::new()
    $enumOpt.RecurseSubdirectories = $Recurse
    if ($IncludeHidden) { $enumOpt.AttributesToSkip -= 2 }
    foreach ($Path in $Paths) {
      $list = @(); $rPath = [FsOrganizer]::GetResolvedPath($Path)
      $dir = Get-Item -Path $rPath
      $files = $dir.GetFiles('*', $enumOpt)
      $group = $files | Group-Object -Property extension
      $group.ForEach({ $list += [FileExtensionInfo]::new($_) })
      # Mark the extension with the largest total size
      $($list | Sort-Object -Property TotalSize, Count)[-1].IsLargest = $true
      $result += $list
    }
    return $result
  }
  static [string] GetFolderAnalysisPrompt([string]$Path, [string]$intent) {
    # .EXAMPLE
    # [FsOrganizer]::GetFolderAnalysisPrompt("~/Downloads/", "Organize files in my downloads path by file use case.")
    $fstats = [FsOrganizer]::GetFiles($Path, $false) | ConvertTo-Json -Depth 4 -WarningAction SilentlyContinue
    $prompt = [FsOrganizer]::GetLocalizedData(".").FileAnalysisPrompt.Replace("<folder_analysis>", $fstats).Replace("<user_intent>", $intent)
    return $prompt
  }
  static [FolderSizeInfo[]] GetFolderSizeInfo([string[]]$Paths) {
    return [FsOrganizer]::GetFolderSizeInfo($Paths, $false)
  }
  static [FolderSizeInfo[]] GetFolderSizeInfo([string[]]$Paths, [bool]$IncludeHidden) {
    # .EXAMPLE
    #  [FsOrganizer]::GetFolderSizeInfo([FsOrganizer]::GetDirectories($pwd, $false).FullName) | Sort-Object Totalsize -Descending
    $result = @()
    foreach ($item in $Paths) {
      $rPath = [FsOrganizer]::GetResolvedPath($item)
      if (![IO.Path]::Exists($rPath)) {
        Write-Warning "Can't find $rPath on $([System.Environment]::MachineName)"
        continue
      }
      $d = [DirectoryInfo]::new($rPath)
      $files = [system.collections.arraylist]::new()
      $IsLeagacy = (Get-Variable 'PSVersionTable' -ValueOnly).psversion.major -le 5
      if ($IsLeagacy) {
        Write-Verbose "Using legacy code"
        # need to account for errors when accessing folders without permissions
        # get files in the root of the folder
        if ($IncludeHidden) {
          $data = $d.GetFiles()
        } else {
          # get files in current location
          $data = $($d.GetFiles()).Where({ $_.attributes -notmatch "hidden" })
        }
        if ($data -and $data.count -gt 1) {
          $files.AddRange($data)
        } elseif ($data -and $data.count -eq 1) {
          [void]$files.Add($data)
        }
        $all = [FsOrganizer]::GetDirectories($rPath, $IncludeHidden)
        # get the files in each subfolder
        if ($all) {
          $($all).Foreach({
              $ErrorActionPreference = "Stop"
              Try {
                $data = $(if ($IncludeHidden) {
                    $(([DirectoryInfo]"$($_.fullname)").GetFiles())
                  } else {
                    $(([DirectoryInfo]"$($_.fullname)").GetFiles()).Where({ $_.Attributes -notmatch "Hidden" })
                  }
                )
                if ($data -and $data.count -gt 1) {
                  $files.AddRange($data)
                } elseif ($data -and $data.count -eq 1) {
                  [void]$files.Add($data)
                }
              } Catch {
                Write-Warning "Failed on $rPath. $($_.exception.message)."
                Clear-Variable data
              }
            }
          )
        }
      }
      If (!$IsLeagacy) {
        #this .NET class is not available in Windows PowerShell 5.1
        $opt = [EnumerationOptions]::new()
        $opt.RecurseSubdirectories = $True

        if ($IncludeHidden) {
          Write-Verbose "Including hidden files"
          $opt.AttributesToSkip = "SparseFile", "ReparsePoint"
        } else {
          $opt.attributestoSkip = "Hidden"
        }

        $data = $($d.GetFiles("*", $opt))
        if ($data -and $data.count -gt 1) {
          $files.AddRange($data)
        } elseif ($data -and $data.count -eq 1) {
          [void]$files.Add($data)
        }
      }
      $totalSize = 0
      $FilesCount = 0
      If ($files.count -gt 0) {
        # there appears to be a bug with the array list in Windows PowerShell
        # where it doesn't always properly enumerate. Passing the list
        # items via ForEach appears to solve the problem and doesn't
        # adversely affect PowerShell 7. Addeed in v2.22.0. JH
        $stats = $files.foreach({ $_ }) | Measure-Object -Property length -Sum
        $totalSize = $stats.sum
        $FilesCount = $stats.count
      }
      $result += [FolderSizeInfo]::new($rPath, $totalSize, $(Split-Path $rPath -Leaf), $FilesCount)
    }
    return $result
  }
  static [FileInfo] GetLastModifiedFile([bool]$Recurse) {
    return [FsOrganizer]::GetLastModifiedFile(".", "*", $Recurse)
  }
  static [FileInfo] GetLastModifiedFile([string]$Path, [string]$Filter, [bool]$Recurse) {
    return [FsOrganizer]::GetLastModifiedFile($Path, $Filter, [TimeInterval]::Hours, 24)
  }
  static [FileInfo] GetLastModifiedFile([string]$Path, [string]$Filter, [TimeInterval]$Interval, [int32]$IntervalCount) {
    return [FsOrganizer]::GetLastModifiedFile($Path, $Filter, $Interval, $IntervalCount, $false)
  }
  static [FileInfo] GetLastModifiedFile([string]$Path, [string]$Filter, [TimeInterval]$Interval, [int32]$IntervalCount, [bool]$Recurse) {
    [ValidateScript({
        # This will write a custom error message if validation fails
        If ((Test-Path -Path $_ -PathType Container) -and ((Get-Item -Path $_).psprovider.name -eq 'Filesystem')) {
          return $True
        } else {
          Throw "The specified Path value $_ is not a valid folder or not a file system location."
          return $False
        }
      }
    )][string]$Path = $Path
    $msg = "Searching {0} for {1} files modified in the last {2} {3}." -f ([FsOrganizer]::GetResolvedPath($Path)), $filter, $IntervalCount, $Interval
    Write-Verbose $msg
    $last = (Get-Date)."Add$Interval"(-$IntervalCount)
    Write-Verbose "Cutoff date is $Last"
    $Params = @{
      Filter  = $Filter
      Path    = [FsOrganizer]::GetResolvedPath($Path)
      File    = $true
      Recurse = $Recurse
    }
    return $(Get-ChildItem @Params).Where({ $_.LastWriteTime -ge $last })
  }
  static [RecentOpenInfo[]] GetRecentlyOpened() {
    $_Home = [Environment]::GetEnvironmentVariable("HOME")
    $hostOs = [FsOrganizer]::GetHostOs()
    $result = @()
    switch ($true) {
      $($hostOs -eq "Windows") {
        # Get recently opened files from Windows Registry
        # [Environment]::GetFolderPath("Recent") ??
        $registryPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        $key = Get-ItemProperty -Path "HKCU:\$registryPath" -ErrorAction SilentlyContinue
        if ($key) {
          $values = Get-ItemProperty -Path "HKCU:\$registryPath" |
            Select-Object -Property * -ExcludeProperty PS*Path, PSChildName, PSDrive |
            ForEach-Object {
              $_.PSObject.Properties | Where-Object { $_.Name -ne "MRUListEx" }
            } | ForEach-Object {
              # Convert binary data to string and remove null terminators
              if ($_.Value) {
                [System.Text.Encoding]::Unicode.GetString($_.Value) -replace "\0.*$"
              }
            } | Where-Object { $_ }
          $result += $values
        }
        break
      }
      $($hostOs -in ("Linux", "FreeBSD")) {
        $recentlyUsedPath = Join-Path $_HOME ".local/share/recently-used.xbel"
        if (Test-Path $recentlyUsedPath) {
          [xml]$xbelContent = Get-Content $recentlyUsedPath
          $xbelContent.xbel.bookmark.Where({ $_.Gettype().Name -eq "XmlElement" }).ForEach({
              $result += [RecentOpenInfo]::new($_)
            }
          )
        }
        break
      }
      $($hostOs -eq "MacOSX") {
        # macOS recent files can be retrieved using SQLite database in ~/Library/Application Support/com.apple.sharedfilelist/
        # TODO: Fix this:
        # - I don't have a mac, never tested this!
        # - This requires additional processing as the file is in a binary format, you might need to use additional tools or APIs to read this properly
        $recentItemsPath = Join-Path $_HOME "Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentDocuments.sfl2"
        if (Test-Path $recentItemsPath) {
          $recentItems = Get-ChildItem -Path (Join-Path $_HOME "Library/Recent")
          $recentItems | Select-Object -ExpandProperty Name
        }
        break
      }
      Default {
        throw "Unsupported OS: $hostOs"
      }
    }
    return $result
  }
  static [string] GetRelativePath([string]$RelativeTo, [string]$Path) {
    # $RelativeTo : The source path the result should be relative to. This path is always considered to be a directory.
    # $Path : The destination path.
    $result = [string]::Empty
    $Drive = $Path -replace "^([^\\/]+:[\\/])?.*", '$1'
    if ($Drive -ne ($RelativeTo -replace "^([^\\/]+:[\\/])?.*", '$1')) {
      Write-Verbose "Paths on different drives"
      return $Path
    }
    $RelativeTo = $RelativeTo -replace "^[^\\/]+:[\\/]", [IO.Path]::DirectorySeparatorChar
    $Path = $Path -replace "^[^\\/]+:[\\/]", [IO.Path]::DirectorySeparatorChar
    $RelativeTo = [IO.Path]::GetFullPath($RelativeTo).TrimEnd('\/') -replace "^[^\\/]+:[\\/]", [IO.Path]::DirectorySeparatorChar
    $Path = [IO.Path]::GetFullPath($Path) -replace "^[^\\/]+:[\\/]", [IO.Path]::DirectorySeparatorChar

    $commonLength = 0
    while ($Path[$commonLength] -eq $RelativeTo[$commonLength]) {
      $commonLength++
    }
    if ($commonLength -eq $RelativeTo.Length -and $RelativeTo.Length -eq $Path.Length) {
      Write-Verbose "Equal Paths"
      return "." # The same paths
    }
    if ($commonLength -eq 0) {
      Write-Verbose "Paths on different drives?"
      return $Drive + $Path
    }
    Write-Verbose "Common base: $commonLength $($RelativeTo.Substring(0,$commonLength))"
    # In case we matched PART of a name, like C:/Users/Joel and C:/Users/Joe
    while ($commonLength -gt $RelativeTo.Length -and ($RelativeTo[$commonLength] -ne [IO.Path]::DirectorySeparatorChar)) {
      $commonLength--
    }
    Write-Verbose "Common base: $commonLength $($RelativeTo.Substring(0,$commonLength))"
    # Create '..' segments for segments past the common on the "$RelativeTo" Path
    if ($commonLength -lt $RelativeTo.Length) {
      $result = @('..') * @($RelativeTo.Substring($commonLength).Split([IO.Path]::DirectorySeparatorChar).Where{ $_ }).Length -join ([IO.Path]::DirectorySeparatorChar)
    }
    return (@($result, $Path.Substring($commonLength).TrimStart([IO.Path]::DirectorySeparatorChar)).Where{ $_ } -join ([IO.Path]::DirectorySeparatorChar))
  }
  static [string] GetResolvedPath([string]$Path) {
    return [FsOrganizer]::GetResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
  }
  static [string] GetResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
    $paths = $session.Path.GetResolvedPSPathFromPSPath($Path);
    if ($paths.Count -gt 1) {
      throw [IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} is ambiguous", $Path))
    } elseif ($paths.Count -lt 1) {
      throw [IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} not Found", $Path))
    }
    return $paths[0].Path
  }
  static [string] GetUnResolvedPath([string]$Path) {
    return [FsOrganizer]::GetUnResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
  }
  static [string] GetUnResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
    return $session.Path.GetUnresolvedProviderPathFromPSPath($Path)
  }
  static [string] GetHostOs() {
    return $(switch ($true) {
        $([RuntimeInformation]::IsOSPlatform([OSPlatform]::Windows)) { "Windows"; break }
        $([RuntimeInformation]::IsOSPlatform([OSPlatform]::FreeBSD)) { "FreeBSD"; break }
        $([RuntimeInformation]::IsOSPlatform([OSPlatform]::Linux)) { "Linux"; break }
        $([RuntimeInformation]::IsOSPlatform([OSPlatform]::OSX)) { "MacOSX"; break }
        Default {
          "UNKNOWN"
        }
      }
    )
  }
  static [PsCustomObject] GetLocalizedData([string]$RootPath) {
    $RootPath = [FsOrganizer]::GetUnResolvedPath($RootPath)
    $psdFile = [FileInfo]::new([IO.Path]::Combine($RootPath, [System.Threading.Thread]::CurrentThread.CurrentCulture.Name, 'cliHelper.filesystem.strings.psd1'))
    if (!$psdFile.Exists) { throw [FileNotFoundException]::new('Unable to find the LocalizedData file!', $psdFile) }
    return [scriptblock]::Create("$([IO.File]::ReadAllText($psdFile))").Invoke()
  }
}

$CurrentCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture.Name
$script:localizedData = if ($null -ne (Get-Command Get-LocalizedData -ErrorAction SilentlyContinue)) {
  Get-LocalizedData -DefaultUICulture $CurrentCulture
} else {
  [FsOrganizer]::GetLocalizedData(".")
}

# Types that will be available to users when they import the module.
$typestoExport = @(
  [FsOrganizer]
)
$TypeAcceleratorsClass = [PsObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
foreach ($Type in $typestoExport) {
  if ($Type.FullName -in $TypeAcceleratorsClass::Get.Keys) {
    $Message = @(
      "Unable to register type accelerator '$($Type.FullName)'"
      'Accelerator already exists.'
    ) -join ' - '

    throw [System.Management.Automation.ErrorRecord]::new(
      [System.InvalidOperationException]::new($Message),
      'TypeAcceleratorAlreadyExists',
      [System.Management.Automation.ErrorCategory]::InvalidOperation,
      $Type.FullName
    )
  }
}
# Add type accelerators for every exportable type.
foreach ($Type in $typestoExport) {
  $TypeAcceleratorsClass::Add($Type.FullName, $Type)
}
# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
  foreach ($Type in $typestoExport) {
    $TypeAcceleratorsClass::Remove($Type.FullName)
  }
}.GetNewClosure();


#endregion Classes
$Private = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -Filter "*.ps1" -ErrorAction SilentlyContinue
$Public = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Public')) -Filter "*.ps1" -ErrorAction SilentlyContinue
# Load dependencies
$PrivateModules = [string[]](Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | Select-Object -ExpandProperty FullName)
if ($PrivateModules.Count -gt 0) {
  ForEach ($Module in $PrivateModules) {
    Try {
      Import-Module $Module -ErrorAction Stop
    } Catch {
      Write-Error "Failed to import module $Module : $_"
    }
  }
}
# Dot source the files
ForEach ($Import in ($Public + $Private)) {
  Try {
    . $Import.fullname
  } Catch {
    Write-Warning "Failed to import function $($Import.BaseName): $_"
    $host.UI.WriteErrorLine($_)
  }
}
# Export Public Functions
$Param = @{
  Function = $Public.BaseName
  # Variable = '*'
  Cmdlet   = '*'
  Alias    = '*'
}
Export-ModuleMember @Param -Verbose
