# [+] [cliHelper.filesystem](https://www.powershellgallery.com/packages/cliHelper.filesystem)

🔥 Blazingly fast, AI-powered file organization tool.

## 🚀 Features

- 🧠 AI-powered file organization
- 📂 Smart directory structuring and file categorization
- ⚡ Blazingly fast PowerShell operations
- 🎯 Natural language commands for file management
- 🛡️ Safe operations with preview and confirmation options

## Usage

- **📝 Requirements**
  - PowerShell 5.1 or higher
  - Valid Anthropic API key
  - PowerShell Core for Linux and MacOsx
- 🏗️ Install from PsGallery
  ```powershell
  Install-Module cliHelper.filesystem

  # Import the module
  Import-Module cliHelper.filesystem

  # Verify installation
  Get-Command -Module cliHelper.filesystem
  ```

Set your Anthropic API key

```powershell
Set-FsOrganizerConfig -ApiKey "your-api-key-here"

# Organize a directory using natural language
Invoke-FsOrganizer -Path "C:\Downloads" -Intent "organize my photos by date and event"

# Preview changes before applying
Invoke-FsOrganizer -Path "D:\Projects" -Intent "group by programming language" -Preview

# Get organization suggestions
Get-FsOrganizerAdvice -Path "C:\Users\Me\Documents"
```

## ⚙️ Config

```powershell
# Set default behavior
Set-FsOrganizerConfig -DefaultConfirmation $true -PreviewChanges $true

# Configure API settings
Set-FsOrganizerConfig -ApiKey "your-api-key" -MaxTokens 2000 -Temperature 0.7
```

## 🤝 Contributing

Pull requests are welcome! Please check out our
[contribution guidelines](CONTRIBUTING.md) for details on how to get started.

## 🎭 License

This project is licensed under the [WTFPL License](LICENSE).

<!-- Made with 💝 by humans and AI working together -->
