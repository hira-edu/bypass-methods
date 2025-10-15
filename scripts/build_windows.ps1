# =============================================================================
# Bypass Methods Framework - Windows Build Script (PowerShell)
# =============================================================================
# This script automates the entire build process for Windows users
# From checking prerequisites to running the final application
# =============================================================================

param(
    [switch]$SkipPrerequisites,
    [switch]$SkipTests,
    [switch]$Verbose,
    [string]$LogFile = "build_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

# Set error action preference
$ErrorActionPreference = "Continue"

# Initialize counters
$ErrorCount = 0
$WarningCount = 0

# Function to write log messages
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path $LogFile -Value $logMessage
}

# Function to check if command exists
function Test-Command {
    param([string]$Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

# Function to increment error count
function Add-Error {
    $script:ErrorCount++
}

# Function to increment warning count
function Add-Warning {
    $script:WarningCount++
}

# Function to download file
function Invoke-Download {
    param([string]$Url, [string]$OutFile)
    try {
        Write-Log "Downloading $OutFile from $Url"
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
        return $true
    } catch {
        Write-Log "Failed to download ${OutFile}: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to install Python
function Install-Python {
    Write-Log "Installing Python..."
    
    $pythonUrl = "https://www.python.org/ftp/python/3.11.8/python-3.11.8-amd64.exe"
    $pythonInstaller = "python_installer.exe"
    
    if (-not (Invoke-Download -Url $pythonUrl -OutFile $pythonInstaller)) {
        Add-Error
        return $false
    }
    
    try {
        Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0" -Wait
        Remove-Item $pythonInstaller -Force
        return $true
    } catch {
        Write-Log "Failed to install Python: $($_.Exception.Message)" "ERROR"
        Add-Error
        return $false
    }
}

# Function to install Visual Studio Build Tools
function Install-VisualStudioBuildTools {
    Write-Log "Installing Visual Studio Build Tools..."
    
    $vsUrl = "https://aka.ms/vs/17/release/vs_buildtools.exe"
    $vsInstaller = "vs_buildtools.exe"
    
    if (-not (Invoke-Download -Url $vsUrl -OutFile $vsInstaller)) {
        Add-Error
        return $false
    }
    
    try {
        $installArgs = @(
            "--quiet",
            "--wait",
            "--norestart",
            "--nocache",
            "--installPath", "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools",
            "--add", "Microsoft.VisualStudio.Workload.VCTools",
            "--add", "Microsoft.VisualStudio.Component.Windows10SDK.19041"
        )
        
        Start-Process -FilePath $vsInstaller -ArgumentList $installArgs -Wait
        Remove-Item $vsInstaller -Force
        return $true
    } catch {
        Write-Log "Failed to install Visual Studio Build Tools: $($_.Exception.Message)" "ERROR"
        Add-Error
        return $false
    }
}

# Function to install CMake
function Install-CMake {
    Write-Log "Installing CMake..."
    
    $cmakeUrl = "https://github.com/Kitware/CMake/releases/download/v3.28.1/cmake-3.28.1-windows-x86_64.msi"
    $cmakeInstaller = "cmake_installer.msi"
    
    if (-not (Invoke-Download -Url $cmakeUrl -OutFile $cmakeInstaller)) {
        Add-Error
        return $false
    }
    
    try {
        Start-Process -FilePath "msiexec" -ArgumentList "/i", $cmakeInstaller, "/quiet", "/norestart" -Wait
        Remove-Item $cmakeInstaller -Force
        $env:PATH += ";C:\Program Files\CMake\bin"
        return $true
    } catch {
        Write-Log "Failed to install CMake: $($_.Exception.Message)" "ERROR"
        Add-Error
        return $false
    }
}

# Function to install Git
function Install-Git {
    Write-Log "Installing Git..."
    
    $gitUrl = "https://github.com/git-for-windows/git/releases/download/v2.43.0.windows.1/Git-2.43.0-64-bit.exe"
    $gitInstaller = "git_installer.exe"
    
    if (-not (Invoke-Download -Url $gitUrl -OutFile $gitInstaller)) {
        Add-Error
        return $false
    }
    
    try {
        Start-Process -FilePath $gitInstaller -ArgumentList "/VERYSILENT", "/NORESTART" -Wait
        Remove-Item $gitInstaller -Force
        $env:PATH += ";C:\Program Files\Git\bin"
        return $true
    } catch {
        Write-Log "Failed to install Git: $($_.Exception.Message)" "ERROR"
        Add-Error
        return $false
    }
}

# Main script execution
try {
    Write-Host ""
    Write-Host "============================================================================="
    Write-Host "ðŸš€ Bypass Methods Framework - Windows Build Script (PowerShell)"
    Write-Host "============================================================================="
    Write-Host "Production-ready DirectX and Windows API hooking framework"
    Write-Host "Automated build process for Windows users"
    Write-Host "============================================================================="
    Write-Host ""
    
    Write-Log "Build started" "INFO"
    
    # =============================================================================
    # PHASE 1: PREREQUISITE CHECKING
    # =============================================================================
    
    if (-not $SkipPrerequisites) {
        Write-Log "PHASE 1: Checking Prerequisites" "INFO"
        Write-Host ""
        
        # Check Windows version
        Write-Log "Checking Windows version..." "INFO"
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem
        if ($osInfo.Version -match "10\.0|11\.0") {
            Write-Log "âœ… Windows version: OK ($($osInfo.Caption))" "INFO"
        } else {
            Write-Log "âŒ ERROR: Windows 10 or 11 required. Current version: $($osInfo.Caption)" "ERROR"
            Add-Error
        }
        
        # Check administrator privileges
        Write-Log "Checking administrator privileges..." "INFO"
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        if ($isAdmin) {
            Write-Log "âœ… Administrator privileges: OK" "INFO"
        } else {
            Write-Log "âš ï¸ WARNING: Not running as administrator. Some features may be limited." "WARNING"
            Add-Warning
        }
        
        # Check Python
        Write-Log "Checking Python installation..." "INFO"
        if (-not (Test-Command "python")) {
            Write-Log "âŒ ERROR: Python not found. Installing Python..." "ERROR"
            if (-not (Install-Python)) {
                throw "Failed to install Python"
            }
        } else {
            $pythonVersion = python --version 2>&1
            Write-Log "âœ… Python found: $pythonVersion" "INFO"
        }
        
        # Check pip
        Write-Log "Checking pip installation..." "INFO"
        if (-not (Test-Command "pip")) {
            Write-Log "âŒ ERROR: pip not found. Installing pip..." "ERROR"
            python -m ensurepip --upgrade
            if ($LASTEXITCODE -ne 0) {
                Write-Log "âŒ ERROR: Failed to install pip" "ERROR"
                Add-Error
            }
        } else {
            $pipVersion = pip --version
            Write-Log "âœ… pip found: $pipVersion" "INFO"
        }
        
        # Check Visual Studio
        Write-Log "Checking Visual Studio installation..." "INFO"
        if (-not (Test-Command "cl")) {
            Write-Log "âŒ ERROR: Visual Studio not found. Installing Visual Studio Build Tools..." "ERROR"
            if (-not (Install-VisualStudioBuildTools)) {
                throw "Failed to install Visual Studio Build Tools"
            }
        } else {
            Write-Log "âœ… Visual Studio found" "INFO"
        }
        
        # Check CMake
        Write-Log "Checking CMake installation..." "INFO"
        if (-not (Test-Command "cmake")) {
            Write-Log "âŒ ERROR: CMake not found. Installing CMake..." "ERROR"
            if (-not (Install-CMake)) {
                throw "Failed to install CMake"
            }
        } else {
            $cmakeVersion = cmake --version
            Write-Log "âœ… CMake found: $($cmakeVersion.Split("`n")[0])" "INFO"
        }
        
        # Check Git
        Write-Log "Checking Git installation..." "INFO"
        if (-not (Test-Command "git")) {
            Write-Log "âŒ ERROR: Git not found. Installing Git..." "ERROR"
            if (-not (Install-Git)) {
                throw "Failed to install Git"
            }
        } else {
            $gitVersion = git --version
            Write-Log "âœ… Git found: $gitVersion" "INFO"
        }
        
        # Prerequisites summary
        Write-Host ""
        Write-Log "PREREQUISITES SUMMARY:" "INFO"
        if ($ErrorCount -gt 0) {
            Write-Log "âŒ $ErrorCount errors found" "ERROR"
            throw "Prerequisites check failed"
        } else {
            Write-Log "âœ… All prerequisites satisfied" "INFO"
            if ($WarningCount -gt 0) {
                Write-Log "âš ï¸ $WarningCount warnings (non-critical)" "WARNING"
            }
        }
    }
    
    # =============================================================================
    # PHASE 2: ENVIRONMENT SETUP
    # =============================================================================
    
    Write-Log "PHASE 2: Setting up Environment" "INFO"
    Write-Host ""
    
    # Create build directory
    Write-Log "Creating build directory..." "INFO"
    if (-not (Test-Path "build")) {
        New-Item -ItemType Directory -Path "build" | Out-Null
    }
    
    # Set up Visual Studio environment
    Write-Log "Setting up Visual Studio environment..." "INFO"
    $vcvarsPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    if (Test-Path $vcvarsPath) {
        & cmd /c "`"$vcvarsPath`" && set" | ForEach-Object {
            if ($_ -match "^([^=]+)=(.*)$") {
                Set-Item -Path "env:$($matches[1])" -Value $matches[2]
            }
        }
    }
    
    # =============================================================================
    # PHASE 3: PYTHON DEPENDENCIES
    # =============================================================================
    
    Write-Log "PHASE 3: Installing Python Dependencies" "INFO"
    Write-Host ""
    
    # Create virtual environment
    Write-Log "Creating Python virtual environment..." "INFO"
    if (Test-Path "venv") {
        Write-Log "Virtual environment already exists, removing..." "INFO"
        Remove-Item -Path "venv" -Recurse -Force
    }
    
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Log "âŒ ERROR: Failed to create virtual environment" "ERROR"
        Add-Error
        throw "Failed to create virtual environment"
    }
    
    # Activate virtual environment
    Write-Log "Activating virtual environment..." "INFO"
    & "venv\Scripts\Activate.ps1"
    if ($LASTEXITCODE -ne 0) {
        Write-Log "âŒ ERROR: Failed to activate virtual environment" "ERROR"
        Add-Error
        throw "Failed to activate virtual environment"
    }
    
    # Upgrade pip
    Write-Log "Upgrading pip..." "INFO"
    python -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        Write-Log "âŒ ERROR: Failed to upgrade pip" "ERROR"
        Add-Error
        throw "Failed to upgrade pip"
    }
    
    # Install Python dependencies
    Write-Log "Installing Python dependencies..." "INFO"
    pip install -r python\requirements\requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Log "âŒ ERROR: Failed to install Python dependencies" "ERROR"
        Add-Error
        throw "Failed to install Python dependencies"
    }
    
    # Install security dependencies
    Write-Log "Installing security dependencies..." "INFO"
    pip install -r python\requirements\requirements_security.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Log "âŒ ERROR: Failed to install security dependencies" "ERROR"
        Add-Error
        throw "Failed to install security dependencies"
    }
    
    # Install Windows-specific dependencies
    Write-Log "Installing Windows-specific dependencies..." "INFO"
    pip install pywin32==306 PyWinCtl==0.3
    if ($LASTEXITCODE -ne 0) {
        Write-Log "âŒ ERROR: Failed to install Windows-specific dependencies" "ERROR"
        Add-Error
        throw "Failed to install Windows-specific dependencies"
    }
    
    # =============================================================================
    # PHASE 4: C++ BUILD
    # =============================================================================
    
    Write-Log "PHASE 4: Building C++ Components" "INFO"
    Write-Host ""
    
    Push-Location build
    
    # Configure CMake
    Write-Log "Configuring CMake..." "INFO"
    cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
    if ($LASTEXITCODE -ne 0) {
        Write-Log "âŒ ERROR: CMake configuration failed" "ERROR"
        Add-Error
        throw "CMake configuration failed"
    }
    
    # Build the project
    Write-Log "Building C++ components..." "INFO"
    cmake --build . --config Release --parallel
    if ($LASTEXITCODE -ne 0) {
        Write-Log "âŒ ERROR: C++ build failed" "ERROR"
        Add-Error
        throw "C++ build failed"
    }
    
    # Run C++ tests
    if (-not $SkipTests) {
        Write-Log "Running C++ tests..." "INFO"
        ctest --test-dir . -C Release --output-on-failure
        if ($LASTEXITCODE -ne 0) {
            Write-Log "âš ï¸ WARNING: Some C++ tests failed (non-critical)" "WARNING"
            Add-Warning
        } else {
            Write-Log "âœ… All C++ tests passed" "INFO"
        }
    }
    
    Pop-Location
    
    # =============================================================================
    # PHASE 5: PYTHON TESTS
    # =============================================================================
    
    if (-not $SkipTests) {
        Write-Log "PHASE 5: Running Python Tests" "INFO"
        Write-Host ""
        
        # Run Python tests
        Write-Log "Running Python tests..." "INFO"
        python -m pytest python\tests\ -v
        if ($LASTEXITCODE -ne 0) {
            Write-Log "âš ï¸ WARNING: Some Python tests failed (non-critical)" "WARNING"
            Add-Warning
        } else {
            Write-Log "âœ… All Python tests passed" "INFO"
        }
        
        # Run security tests
        Write-Log "Running security tests..." "INFO"
        python python\tools\security_tester.py
        if ($LASTEXITCODE -ne 0) {
            Write-Log "âš ï¸ WARNING: Some security tests failed (non-critical)" "WARNING"
            Add-Warning
        } else {
            Write-Log "âœ… All security tests passed" "INFO"
        }
    }
    
    # =============================================================================
    # PHASE 6: FINAL SETUP
    # =============================================================================
    
    Write-Log "PHASE 6: Final Setup" "INFO"
    Write-Host ""
    
    # Create shortcuts
    Write-Log "Creating desktop shortcuts..." "INFO"
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Bypass Methods Framework.lnk")
    $LaunchPath = Join-Path (Get-Location).Path 'launch_framework.bat'
    $Shortcut.TargetPath = $LaunchPath
    $Shortcut.WorkingDirectory = (Get-Location).Path
    $Shortcut.Description = "Bypass Methods Framework GUI Controller"
    $Shortcut.Save()
    Write-Log "âœ… Desktop shortcut created" "INFO"
    
    # Create start menu entry
    Write-Log "Creating start menu entry..." "INFO"
    $startMenuPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Bypass Methods Framework"
    if (-not (Test-Path $startMenuPath)) {
        New-Item -ItemType Directory -Path $startMenuPath | Out-Null
    }
    $Shortcut = $WshShell.CreateShortcut("$startMenuPath\Bypass Methods Framework.lnk")
    $Shortcut.TargetPath = $LaunchPath
    $Shortcut.WorkingDirectory = (Get-Location).Path
    $Shortcut.Description = "Bypass Methods Framework GUI Controller"
    $Shortcut.Save()
    Write-Log "âœ… Start menu entry created" "INFO"
    
    # Create launch script
    Write-Log "Creating launch script..." "INFO"
    @"
@echo off
echo Starting Bypass Methods Framework...
call venv\Scripts\activate.bat
python python\tools\gui_controller.py
pause
"@ | Out-File -FilePath "launch_framework.bat" -Encoding ASCII
    Write-Log "âœ… Launch script created" "INFO"
    
    # =============================================================================
    # PHASE 7: VERIFICATION
    # =============================================================================
    
    Write-Log "PHASE 7: Final Verification" "INFO"
    Write-Host ""
    
    # Check file integrity
    Write-Log "Checking file integrity..." "INFO"
    if (Test-Path "build\Release\*.dll") {
        Write-Log "âœ… C++ DLLs built successfully" "INFO"
    } else {
        Write-Log "âŒ ERROR: C++ DLLs not found" "ERROR"
        Add-Error
    }
    
    if (Test-Path "python\tools\gui_controller.py") {
        Write-Log "âœ… Python tools available" "INFO"
    } else {
        Write-Log "âŒ ERROR: Python tools not found" "ERROR"
        Add-Error
    }
    
    # =============================================================================
    # FINAL SUMMARY
    # =============================================================================
    
    Write-Host ""
    Write-Host "============================================================================="
    Write-Log "BUILD COMPLETED" "INFO"
    Write-Host "============================================================================="
    
    if ($ErrorCount -gt 0) {
        Write-Log "âŒ BUILD FAILED: $ErrorCount errors" "ERROR"
        Write-Host ""
        Write-Log "ERRORS FOUND:" "ERROR"
        Write-Log "Please check the log file: $LogFile" "ERROR"
        Write-Host ""
        Write-Log "TROUBLESHOOTING:" "ERROR"
        Write-Log "1. Run as administrator" "ERROR"
        Write-Log "2. Check Windows Defender/firewall settings" "ERROR"
        Write-Log "3. Ensure Visual Studio Build Tools are installed" "ERROR"
        Write-Log "4. Check internet connection for downloads" "ERROR"
        exit 1
    } else {
        Write-Log "BUILD SUCCESSFUL" "INFO"
        if ($WarningCount -gt 0) { Write-Log "$WarningCount warnings (non-critical)" "WARNING" }
        Write-Host ""
        Write-Log "NEXT STEPS:" "INFO"
        Write-Log "1. Double-click 'launch_framework.bat' to start" "INFO"
        Write-Log "2. Or use the desktop shortcut" "INFO"
        Write-Log "3. Or run: python python\tools\gui_controller.py" "INFO"
        Write-Host ""
        Write-Log "DOCUMENTATION:" "INFO"
        Write-Log "User Guide: docs\USER_GUIDE.md" "INFO"
        Write-Log "API Reference: docs\API_REFERENCE.md" "INFO"
        Write-Log "Architecture: docs\ARCHITECTURE.md" "INFO"
        Write-Host ""
        Write-Log "SUPPORT:" "INFO"
        Write-Log "Issues: GitHub Issues" "INFO"
        Write-Log "Discussions: GitHub Discussions" "INFO"
        Write-Log "Security: SECURITY.md" "INFO"
    }
} catch {
    Write-Log "âŒ BUILD FAILED: $($_.Exception.Message)" "ERROR"
    Write-Host ""
    Write-Log "Please check the log file: $LogFile" "ERROR"
    exit 1
} finally {
    # Clean up
    if (Get-Command "deactivate" -ErrorAction SilentlyContinue) {
        deactivate
    }
    
    Write-Host ""
    Write-Host "============================================================================="
    Write-Log "Build completed at $(Get-Date)" "INFO"
    Write-Host "============================================================================="
    Write-Host ""
} 



