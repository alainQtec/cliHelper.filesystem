
@{
  ModuleName         = 'cliHelper.filesystem'
  ModuleVersion      = [version]'0.1.0'
  ReleaseNotes       = '# Release Notes

## Version _0.1.0_

### New Features

- Added feature abc.
- Added feature defg.

## Changelog

  >...'
  FileAnalysisPrompt = @"
Below are the contents of folder_analysis json provided by the user;
analyze it and suggest logical "file categories" based on each file's name and potential use case
"file categories" can be anything based on the use of the file.
Note the abbreviations that were used in the folder_analysis json:
"N" for Name (file name) and "I" is for Id (file's unique Index).

<folder_analysis>

User Intent: <user_intent>

Based on files in the json and the user intent, suggest appropriate category names.
Make sure to not skip any file and use Ids ("I"s) as provided in folder_analysis json and only return a plaintext output formated like:

'CategoryName' = ('5', '9');
'CategoryName2' = ('2');

You are to only return plaintext, no explanation or anything else.
"@
}
