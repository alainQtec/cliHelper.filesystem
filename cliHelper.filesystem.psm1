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
class FsOrganizer {
  #.SYNOPSIS
  # Uses AI to understand and organize files intuitively
  FsOrganizer() {}

  static [DirectoryInfo[]] GetDirectories([string]$Path, [bool]$Recurse, [bool]$IncludeHidden) {
    [string]$path = Resolve-Path -LiteralPath $path
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
  static [FileExtensionInfo[]] GetFileExtensionInfo([string[]]$Paths) {
    return [FsOrganizer]::GetFileExtensionInfo($Paths, $false, $false)
  }
  static [FileExtensionInfo[]] GetFileExtensionInfo([string[]]$Paths, [bool]$Recurse, [bool]$IncludeHidden) {
    $result = @(); foreach ($Path in $Paths) {
      $rPath = Resolve-Path -Path $Path
      Try {
        $enumOpt = [IO.EnumerationOptions]::new()
      } Catch {
        Throw "This commands requires PowerShell 7."
      }
      $list = @(); $enumOpt.RecurseSubdirectories = $Recurse
      if ($IncludeHidden) { $enumOpt.AttributesToSkip -= 2 }
      $dir = Get-Item -Path $rPath
      $files = $dir.GetFiles('*', $enumOpt)
      $group = $files | Group-Object -Property extension
      #Group and measure
      foreach ($item in $group) {
        $measure = $item.Group | Measure-Object -Property length -Minimum -Maximum -Average -Sum
        $list += [FileExtensionInfo]::Create(@{
            Path         = $rPath
            Extension    = $item.Name
            Count        = $item.Count
            TotalSize    = $measure.Sum
            SmallestSize = $measure.Minimum
            LargestSize  = $measure.Maximum
            AverageSize  = $measure.Average
            Computername = [system.environment]::MachineName
            ReportDate   = Get-Date
            Files        = $item.group
            IsLargest    = $False
          }
        )
      }
      # Mark the extension with the largest total size
      $($list | Sort-Object -Property TotalSize, Count)[-1].IsLargest = $true
      Update-TypeData -TypeName FileExtensionInfo -MemberType AliasProperty -MemberName Total -Value TotalSize -Force
      $result += $list
    }
    return $result
  }
  static [FolderSizeInfo[]] GetFolderSizeInfo([string[]]$Paths) {
    return [FsOrganizer]::GetFolderSizeInfo($Paths, $false)
  }
  static [FolderSizeInfo[]] GetFolderSizeInfo([string[]]$Paths, [bool]$IncludeHidden) {
    # .EXAMPLE
    #  [FsOrganizer]::GetFolderSizeInfo([FsOrganizer]::GetDirectories($pwd, $false).FullName) | Sort-Object Totalsize -Descending
    $result = @()
    foreach ($item in $Paths) {
      $rPath = Resolve-Path -LiteralPath $item
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
          [void]($files.Add($data))
        }
        $all = [FsOrganizer]::GetDirectories($rPath, $IncludeHidden)
        # get the files in each subfolder
        if ($all) {
          Write-Verbose "Getting files from $($all.count) subfolders"
          $($all).Foreach({
              Write-Verbose $_.fullname
              $ErrorActionPreference = "Stop"
              Try {
                $data = $(if ($IncludeHidden) {
                    $(([DirectoryInfo]"$($_.fullname)").GetFiles())
                  } else {
                    $(([DirectoryInfo]"$($_.fullname)").GetFiles()).where({ $_.Attributes -notmatch "Hidden" })
                  }
                )
                if ($data -and $data.count -gt 1) {
                  $files.AddRange($data)
                } elseif ($data -and $data.count -eq 1) {
                  [void]($files.Add($data))
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
          [void]($files.Add($data))
        }
      }
      If ($files.count -gt 0) {
        # there appears to be a bug with the array list in Windows PowerShell
        # where it doesn't always properly enumerate. Passing the list
        # items via ForEach appears to solve the problem and doesn't
        # adversely affect PowerShell 7. Addeed in v2.22.0. JH
        $stats = $files.foreach( { $_ }) | Measure-Object -Property length -Sum
        $totalFiles = $stats.count
        $totalSize = $stats.sum
      } else {
        $totalFiles = 0
        $totalSize = 0
      }
      $result += [FolderSizeInfo]::Create(@{
          Computername = [System.Environment]::MachineName
          Path         = $rPath
          Name         = $(Split-Path $rPath -Leaf)
          TotalFiles   = $totalFiles
          TotalSize    = $totalSize
        }
      )
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
        #this will write a custom error message if validation fails
        If ((Test-Path -Path $_ -PathType Container) -and ((Get-Item -Path $_).psprovider.name -eq 'Filesystem')) {
          return $True
        } else {
          Throw "The specified Path value $_ is not a valid folder or not a file system location."
          return $False
        }
      }
    )][string]$Path = $Path
    $msg = "Searching {0} for {1} files modified in the last {2} {3}." -f (Resolve-Path $Path), $filter, $IntervalCount, $Interval
    Write-Verbose $msg
    $last = (Get-Date)."Add$Interval"(-$IntervalCount)
    Write-Verbose "Cutoff date is $Last"
    $Params = @{
      Filter  = $Filter
      Path    = Resolve-Path $Path
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
  static [PSCustomObject] GetLocalizedData([string]$RootPath) {
    [void][Directory]::SetCurrentDirectory($RootPath)
    $psdFile = [FileInfo]::new([IO.Path]::Combine($RootPath, [System.Threading.Thread]::CurrentThread.CurrentCulture.Name, 'cliHelper.filesystem.strings.psd1'))
    if (!$psdFile.Exists) { throw [FileNotFoundException]::new('Unable to find the LocalizedData file!', $psdFile) }
    return [scriptblock]::Create("$([IO.File]::ReadAllText($psdFile))").Invoke()
  }
}

$CurrentCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture.Name
$script:localizedData = if ($null -ne (Get-Command Get-LocalizedData -ErrorAction SilentlyContinue)) {
  Get-LocalizedData -DefaultUICulture $CurrentCulture
} else {
  [FsOrganizer]::GetLocalizedData((Resolve-Path .).Path)
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
