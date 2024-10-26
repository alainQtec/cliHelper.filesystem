﻿function Get-Shortcut {
  <#
    .SYNOPSIS
        Get information about a Shortcut (.lnk file)
    .DESCRIPTION
        Get information about a Shortcut (.lnk file)
    .PARAMETER Path
        Path to .lnk file
    .EXAMPLE
        Get-Shortcut -path C:\portable\test2.lnk

        LinkPath     : C:\portable\test2.lnk
        Link         : test2.lnk
        TargetPath   : C:\Windows\System32\ncpa.cpl
        Target       : ncpa.cpl
        Arguments    :
        Hotkey       :
        WindowStyle  : Normal
        IconLocation : %SystemRoot%\system32\ncpa.cpl,0
        RunAsAdmin   : False
    .NOTES
        Updates:
        * added code to determine RunAsAdmin status
        * added code to display WindowStyle as text as opposed to an integer

        Main function inspired by:
        https://stackoverflow.com/questions/484560/editing-shortcut-lnk-properties-with-powershell

        Checking for RunAsAdmin inspired by:
        https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/managing-shortcut-files-part-3
    #>
  [CmdletBinding(ConfirmImpact = 'None')]
  param(
    [string] $Path
  )

  begin {
    Write-Host $MyInvocation
    $Obj = New-Object -ComObject WScript.Shell
  }

  process {
    if (Test-Path -Path $Path) {
      [array] $ResolveFile = Resolve-Path -Path $Path
      if ($ResolveFile.count -gt 1) {
        Write-Error -Message "ERROR: File specification [$File] resolves to more than 1 file."
      } else {
        Write-Verbose "Using file [$ResolveFile] in section [$Section], getting comments"
        $ResolveFile = Get-Item -Path $ResolveFile
        if ($ResolveFile.Extension -eq '.lnk') {
          $Link = $Obj.CreateShortcut($ResolveFile.FullName)

          $Info = ([ordered] @{})
          $Info.LinkPath = $Link.FullName
          $Info.Link = try { Split-Path -Path $Info.LinkPath -Leaf } catch { 'n/a' }

          $Info.TargetPath = $Link.TargetPath
          $Info.Target = try { Split-Path -Path $Info.TargetPath -Leaf } catch { 'n/a' }
          $Info.Arguments = $Link.Arguments
          $Info.Hotkey = $Link.Hotkey
          $Info.WindowStyle = $( switch ($Link.WindowStyle) {
              1 { 'Normal' }
              3 { 'Maximized' }
              7 { 'Minimized' }
            }
          )
          $Info.IconLocation = $Link.IconLocation
          $Info.RunAsAdmin = $(
            $Bytes = [System.IO.File]::ReadAllBytes($ResolveFile)
            if ($Bytes[0x15] -band 0x20) { $true } else { $false }
          )
          $Info.Description = $Link.Description
          New-Object -TypeName PSObject -Property $Info
        } else {
          Write-Error -Message 'Extension is not .lnk'
        }
      }
    } else {
      Write-Error -Message "ERROR: File [$Path] does not exist"
    }
  }

  end {
    Write-Verbose -Message "Complete."
  }
}

function New-Shortcut {
  <#
.SYNOPSIS
    This script is used to create a  shortcut.
.DESCRIPTION
    This script uses a Com Object to create a shortcut.
.PARAMETER Path
    The path to the shortcut file.  .lnk will be appended if not specified.  If the folder name doesn't exist, it will be created.
.PARAMETER TargetPath
    Full path of the target executable or file.
.PARAMETER Arguments
    Arguments for the executable or file.
.PARAMETER Description
    Description of the shortcut.
.PARAMETER HotKey
    Hotkey combination for the shortcut.  Valid values are SHIFT+F7, ALT+CTRL+9, etc.  An invalid entry will cause the function to fail.
.PARAMETER WorkDir
    Working directory of the application.  An invalid directory can be specified, but invoking the application from the shortcut could fail.
.PARAMETER WindowStyle
    Windows style of the application, Normal (1), Maximized (3), or Minimized (7).  Invalid entries will result in Normal behavior.
.PARAMETER IconLocation
    Full path of the icon file.  Executables, DLLs, etc with multiple icons need the number of the icon to be specified, otherwise the first icon will be used, i.e.:  c:\windows\system32\shell32.dll,99
.PARAMETER RunAsAdmin
    Used to create a shortcut that prompts for admin credentials when invoked, equivalent to specifying runas.
.PARAMETER Interactive
    Switch that will display the shortcut just created.
.NOTES
    * Added -Interactive switch to display created shortcut
    * Updated -WindowStyle to accept readable content of 'Normal', 'Maximized', 'Minimized' and write correct integer values to shortcut
    * Updated -IconLocation renamed from -Icon to match the output of Get-Shortcut
    * Updated -RunAsAdmin renamed from -Admin and altered code to make more consistent

    Main logic inspired by:
    https://gallery.technet.microsoft.com/scriptcenter/New-Shortcut-4d6fb3d8

    Run as admin inspired by:
    https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/managing-shortcut-files-part-3
.INPUTS
    Strings and Integer
.OUTPUTS
    [psobject]
.EXAMPLE
    New-Shortcut -Path c:\temp\notepad.lnk -TargetPath c:\windows\notepad.exe -Interactive

    Creates a simple shortcut to Notepad at c:\temp\notepad.lnk Function would return:

    LinkPath     : C:\temp\notepad.lnk
    Link         : notepad.lnk
    TargetPath   : C:\Windows\notepad.exe
    Target       : notepad.exe
    Arguments    :
    Hotkey       :
    WindowStyle  : Normal
    IconLocation : ,0
    RunAsAdmin   : False
    Description  :
.EXAMPLE
    New-Shortcut "$($env:Public)\Desktop\Notepad" c:\windows\notepad.exe -WindowStyle 3 -RunAsAdmin

    Creates a shortcut named Notepad.lnk on the Public desktop to notepad.exe that launches maximized after prompting for admin credentials.
.EXAMPLE
    New-Shortcut "$($env:USERPROFILE)\Desktop\Notepad.lnk" c:\windows\notepad.exe -IconLocation "c:\windows\system32\shell32.dll,99"

    Creates a shortcut named Notepad.lnk on the user's desktop to notepad.exe that has a pointy finger icon (on Windows 7).
.EXAMPLE
    New-Shortcut "$($env:USERPROFILE)\Desktop\Notepad.lnk" c:\windows\notepad.exe C:\instructions.txt

    Creates a shortcut named Notepad.lnk on the user's desktop to notepad.exe that opens C:\instructions.txt
.EXAMPLE
    New-Shortcut "$($env:USERPROFILE)\Desktop\ADUC" %SystemRoot%\system32\dsa.msc -Admin

    Creates a shortcut named ADUC.lnk on the user's desktop to Active Directory Users and Computers that launches after prompting for admin credentials
.EXAMPLE
    New-Shortcut -Path F:\DNE\notepad.lnk -TargetPath c:\windows\notepad.exe -Interactive

    If run on a system that does NOT have an F: drive it will return the following:

    New-Shortcut : Unable to create [f:\DNE], shortcut cannot be created
    At line:1 char:1
    + New-Shortcut -Path f:\DNE\notepad.lnk -TargetPath c:\windows\notepad. ...
    + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
        + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,New-Shortcut
#>

  #region Parameters
  [CmdletBinding(SupportsShouldProcess)]
  [OutputType('psobject')]
  param(
    [Parameter(Mandatory, HelpMessage = 'Enter the path to the shortcut you want to create/update', ValueFromPipelineByPropertyName, Position = 0)]
    [Alias('File', 'Shortcut')]
    [string] $Path,

    [Parameter(Mandatory, HelpMessage = 'Enter the path to the program or file you want to run', ValueFromPipelineByPropertyName, Position = 1)]
    [string] $TargetPath,

    [Parameter(ValueFromPipelineByPropertyName, Position = 2)]
    [Alias('Args')]
    [string] $Arguments,

    [Parameter(ValueFromPipelineByPropertyName, Position = 3)]
    [string] $Description,

    [Parameter(ValueFromPipelineByPropertyName, Position = 4)]
    [string] $HotKey,

    [Parameter(ValueFromPipelineByPropertyName, Position = 5)]
    [Alias('WorkingDirectory', 'WorkingDir')]
    [string] $WorkDir,

    [Parameter(ValueFromPipelineByPropertyName, Position = 6)]
    [ValidateSet('1', 'Normal', 3, 'Maximized', 7, 'Minimized')]
    [string] $WindowStyle = 'Normal',

    [Parameter(ValueFromPipelineByPropertyName, Position = 7)]
    [string] $IconLocation,

    [Parameter(ValueFromPipelineByPropertyName)]
    [switch] $RunAsAdmin,

    [switch] $Interactive
  )
  #endregion Parameters

  begin {
    Write-Host $MyInvocation
  }

  process {
    If (!($Path -match '^.*(\.lnk)$')) {
      $Path = "$Path`.lnk"
    }
    [System.IO.FileInfo] $Path = $Path
    $ShouldMessage = "WHATIF: Would create SHORTCUT [$($path.fullname)] ARGUMENTS [$($Arguments)] DESCRIPTION [$($Description)] HOTKEY [$($HotKey)]`nWORKDIR [$($WorkDir)] WINDOWSTYLE [$($WindowStyle)] ICON [$($IconLocation)]"
    if ($PSCmdlet.ShouldProcess($ShouldMessage)) {
      try {
        If (!(Test-Path -Path $Path.DirectoryName)) {
          mkdir -Path $Path.DirectoryName -ErrorAction Stop | Out-Null
        }
      } catch {
        Write-Error -Message "Unable to create [$($Path.DirectoryName)], shortcut cannot be created"
        break
      }
      # Define Shortcut Properties
      $WshShell = New-Object -ComObject WScript.Shell
      $Shortcut = $WshShell.CreateShortcut($Path.FullName)
      $Shortcut.TargetPath = $TargetPath
      $Shortcut.Arguments = $Arguments
      $Shortcut.Description = $Description
      $Shortcut.HotKey = $HotKey
      $Shortcut.WorkingDirectory = $WorkDir
      switch ($WindowStyle) {
        'Normal' { $WindowStyle = 1 }
        'Maximized' { $WindowStyle = 3 }
        'Minimized' { $WindowStyle = 7 }
      }
      $Shortcut.WindowStyle = $WindowStyle
      if ($IconLocation) {
        $Shortcut.IconLocation = $IconLocation
      }
      try {
        $Shortcut.Save()
        $Bytes = [System.IO.File]::ReadAllBytes($Path.FullName)
        if ($RunAsAdmin) {
          $bytes[0x15] = $bytes[0x15] -bor 0x20
        } else {
          $bytes[0x15] = $bytes[0x15] -band -not 0x20
        }
        [System.IO.File]::WriteAllBytes($path.FullName, $bytes)
        if ($Interactive) {
          Get-Shortcut -Path $Path.FullName
        }
      } catch {
        Write-Error -Message "Unable to create shortcut [$($Path.FullName)]"
        break
      }
    }
  }

  end {
    Write-Verbose -Message "Complete."
  }
}

