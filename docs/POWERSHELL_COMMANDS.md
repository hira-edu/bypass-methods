# PowerShell One-Liners (Advanced Configuration Profiles)

All commands below are copy/paste friendly single lines modeled after:

```
iwr "<url>" -OutFile "$env:TEMP\tool.exe"; & "$env:TEMP\tool.exe" <args>
```

**Assumptions**
- Repository path is stored once: `$env:BYPASS_REPO = "C:\Users\Workstation\Documents\GitHub\bypass-methods"`.
- Before running any command, execute `Set-Location $env:BYPASS_REPO`.
- `config.json` already contains the advanced defaults we authored.
- Commands rely on built-in PowerShell + Python 3.11.

---

## 1. Environment Bootstrap

| Purpose | One-Liner |
| --- | --- |
| Install Python 3.11.8 silently | `iwr "https://www.python.org/ftp/python/3.11.8/python-3.11.8-amd64.exe" -OutFile "$env:TEMP\python311.exe"; & "$env:TEMP\python311.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0` |
| Install Visual Studio 2022 Build Tools (+Win10 SDK) | `iwr "https://aka.ms/vs/17/release/vs_buildtools.exe" -OutFile "$env:TEMP\vs_buildtools.exe"; & "$env:TEMP\vs_buildtools.exe" --quiet --wait --norestart --nocache --installPath "$env:ProgramFiles(x86)\Microsoft Visual Studio\2022\BuildTools" --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.Windows10SDK.19041` |
| Install CMake 3.28.1 | `iwr "https://github.com/Kitware/CMake/releases/download/v3.28.1/cmake-3.28.1-windows-x86_64.msi" -OutFile "$env:TEMP\cmake.msi"; & msiexec /i "$env:TEMP\cmake.msi" /quiet /norestart` |
| Install Git 2.43 silently | `iwr "https://github.com/git-for-windows/git/releases/download/v2.43.0.windows.1/Git-2.43.0-64-bit.exe" -OutFile "$env:TEMP\git.exe"; & "$env:TEMP\git.exe" /VERYSILENT /NORESTART` |

---

## 2. Repository & Artifact Handling

| Action | One-Liner |
| --- | --- |
| Fresh clone (ZIP) | `iwr "https://github.com/your-org/bypass-methods/archive/refs/heads/main.zip" -OutFile "$env:TEMP\bypass.zip"; & tar -xf "$env:TEMP\bypass.zip" -C "C:\Users\Workstation\Documents\GitHub"; Rename-Item "C:\Users\Workstation\Documents\GitHub\bypass-methods-main" "bypass-methods"` |
| Release artifact download | `iwr "https://github.com/hira-edu/bypass-methods/releases/latest/download/securityhooked.exe" -OutFile "$env:BYPASS_REPO\artifacts\securityhooked.exe"` |
| SecurityHooked scan (LockDown Browser family) | `pwsh -NoLogo -Command "$tool='$env:BYPASS_REPO\artifacts\securityhooked.exe'; if (!(Test-Path $tool)) { iwr 'https://github.com/hira-edu/bypass-methods/releases/latest/download/securityhooked.exe' -OutFile $tool }; & $tool --comprehensive --target 'lockdownbrowser.exe' --target 'lockdownbrowseroem.exe' --target 'lockdown.exe'"` |
| SecurityHooked scan for ProProctor (PSI) | `pwsh -NoLogo -Command "$tool='$env:BYPASS_REPO\artifacts\securityhooked.exe'; if (!(Test-Path $tool)) { iwr 'https://github.com/hira-edu/bypass-methods/releases/latest/download/securityhooked.exe' -OutFile $tool }; & $tool --comprehensive --target 'proproctor.exe' --target 'proproctordesktop.exe' --target 'psi_proctor_launcher.exe'"` |
| SecurityHooked scan for ETS Secure Browser | `pwsh -NoLogo -Command "$tool='$env:BYPASS_REPO\artifacts\securityhooked.exe'; if (!(Test-Path $tool)) { iwr 'https://github.com/hira-edu/bypass-methods/releases/latest/download/securityhooked.exe' -OutFile $tool }; & $tool --comprehensive --target 'etsbrowser.exe' --target 'etsbrowser64.exe'"` |
| SecurityHooked scan for Prometric clients | `pwsh -NoLogo -Command "$tool='$env:BYPASS_REPO\artifacts\securityhooked.exe'; if (!(Test-Path $tool)) { iwr 'https://github.com/hira-edu/bypass-methods/releases/latest/download/securityhooked.exe' -OutFile $tool }; & $tool --comprehensive --target 'prometricsecurewrapper.exe' --target 'prometricdevicemonitor.exe'"` |

---

## 3. Build & Test Pipelines (CMake)

| Scenario | One-Liner |
| --- | --- |
| Configure Release | `pwsh -NoLogo -Command "Set-Location $env:BYPASS_REPO; cmake -S . -B build -G 'Visual Studio 16 2019' -A x64 -DCMAKE_BUILD_TYPE=Release"` |
| Build Release | `pwsh -NoLogo -Command "Set-Location $env:BYPASS_REPO; cmake --build build --config Release --parallel"` |
| Configure Debug + Coverage | `pwsh -NoLogo -Command "Set-Location $env:BYPASS_REPO; cmake -S . -B build-debug -G 'Visual Studio 16 2019' -A x64 -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON"` |
| Build Debug | `pwsh -NoLogo -Command "Set-Location $env:BYPASS_REPO; cmake --build build-debug --config Debug --parallel"` |
| Run C++ tests | `pwsh -NoLogo -Command "Set-Location $env:BYPASS_REPO; ctest --test-dir build -C Release --output-on-failure"` |
| Run Python tests | `pwsh -NoLogo -Command "Set-Location $env:BYPASS_REPO\python\tests; python automated_test.py --test-suite basic"` |

---

## 4. Capture Profiles (config.json mutations + execution)

> Each command rewrites `config.json` using advanced defaults, switches the capture method, then launches the GUI controller headlessly for smoke validation.

| Capture Mode | One-Liner |
| --- | --- |
| Windows Graphics Capture | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.capture.method='windows_graphics_capture'; $cfg.capture.focus_window_enforcement=$true; $cfg.capture.multi_monitor=$true; $cfg | ConvertTo-Json -Depth 8 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\gui_controller.py --test"` |
| DXGI Desktop Duplication | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.capture.method='dxgi_desktop_duplication'; $cfg.capture.fallback_chain=@('dxgi_desktop_duplication','windows_graphics_capture','direct3d_capture','gdi_capture'); $cfg | ConvertTo-Json -Depth 8 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\gui_controller.py --test"` |
| Direct3D Capture | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.capture.method='direct3d_capture'; $cfg.capture.hardware_acceleration=$true; $cfg.capture.buffer_size=20971520; $cfg | ConvertTo-Json -Depth 8 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\gui_controller.py --test"` |
| GDI Capture Fallback | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.capture.method='gdi_capture'; $cfg.capture.quality='medium'; $cfg.capture.compression=$false; $cfg | ConvertTo-Json -Depth 8 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\gui_controller.py --test"` |

---

## 5. Hook Profiles

| Profile | One-Liner |
| --- | --- |
| DirectX + Windows API Hooks | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.hooks.directx.enabled=$true; $cfg.hooks.windows_api.enabled=$true; $cfg.hooks.keyboard.enabled=$false; $cfg.hooks.process.enabled=$false; $cfg | ConvertTo-Json -Depth 8 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\injector.py --config $cfgPath --hooks directx,windows_api"` |
| Keyboard Interception | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.hooks.keyboard.enabled=$true; $cfg.hooks.keyboard.blocked_keys=@('F12','VK_SNAPSHOT','VK_PRINT'); $cfg | ConvertTo-Json -Depth 8 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\injector.py --config $cfgPath --hooks keyboard"` |
| Process Guard Mode | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.hooks.process.enabled=$true; $cfg.hooks.process.allowlist_mode=$false; $cfg.hooks.process.blocked_processes=@('lockdownbrowser.exe','lockdownbrowseroem.exe','proctortrack.exe','remoteproctor.exe','proproctor.exe','proproctordesktop.exe','etsbrowser.exe','etsbrowser64.exe','prometricsecurewrapper.exe','prometricdevicemonitor.exe'); $cfg | ConvertTo-Json -Depth 8 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\injector.py --config $cfgPath --hooks process"` |

---

## 6. Performance & Monitoring Profiles

| Profile | One-Liner |
| --- | --- |
| High-Frequency Monitoring (250 ms) | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.performance.monitoring=$true; $cfg.performance.sampling_interval=250; $cfg.performance.memory_tracking=$true; $cfg.performance.limits.max_cpu_usage=75; $cfg | ConvertTo-Json -Depth 8 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\gui_controller.py --test"` |
| Memory Stress Profile | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.performance.optimization.memory_pool=$true; $cfg.performance.limits.max_memory_usage=1073741824; $cfg.performance.leak_threshold=524288; $cfg | ConvertTo-Json -Depth 8 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\gui_controller.py --test"` |

---

## 7. Security Profiles

| Profile | One-Liner |
| --- | --- |
| Anti-Detection Max | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.security.anti_detection.enabled=$true; $cfg.security.anti_detection.hook_concealment=$true; $cfg.security.anti_detection.timing_normalization=$true; $cfg.security.anti_detection.call_stack_spoofing=$true; $cfg.security.anti_detection.api_throttling=$true; $cfg | ConvertTo-Json -Depth 10 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\security_tester.py --all"` |
| Obfuscation & Integrity Hardening | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.security.obfuscation.enabled=$true; $cfg.security.integrity.enabled=$true; $cfg.security.integrity.secure_loader=$true; $cfg | ConvertTo-Json -Depth 10 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\security_tester.py --integrity --obfuscation"` |

---

## 8. Logging & Telemetry

| Purpose | One-Liner |
| --- | --- |
| Force structured DEBUG logging | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.logging.level='DEBUG'; $cfg.logging.structured=$true; $cfg.logging.file='logs/undownunlock_advanced.log'; $cfg | ConvertTo-Json -Depth 6 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\gui_controller.py --test"` |
| Tail advanced log | `pwsh -NoLogo -Command "Set-Location $env:BYPASS_REPO; Get-Content .\logs\undownunlock_advanced.log -Wait"` |

---

## 9. Shared Memory Transport

| Scenario | One-Liner |
| --- | --- |
| Increase buffer & enable encryption | `pwsh -NoLogo -Command "$cfgPath='$env:BYPASS_REPO\config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; $cfg.shared_memory.size=20971520; $cfg.shared_memory.encryption=$true; $cfg.shared_memory.integrity_checks=$true; $cfg | ConvertTo-Json -Depth 8 | Set-Content $cfgPath; python $env:BYPASS_REPO\python\tools\gui_controller.py --test"` |

---

## 10. Security Testing Framework (Target Variants)

| Target Sweep | One-Liner |
| --- | --- |
| LockDown Browser family | `iwr "https://github.com/hira-edu/security-testing-framework/releases/download/v3.1.0/SecurityTestingFramework.exe" -OutFile "$env:TEMP\stf.exe"; & "$env:TEMP\stf.exe" --comprehensive --target "lockdownbrowser.exe" --target "lockdownbrowseroem.exe" --target "lockdown.exe"` |
| Custom executables | `iwr "https://github.com/hira-edu/security-testing-framework/releases/download/v3.1.0/SecurityTestingFramework.exe" -OutFile "$env:TEMP\stf.exe"; & "$env:TEMP\stf.exe" --comprehensive --target "undownunlock.exe" --target "undownunlock_oem.exe"` |

---

Use these commands as templates-swap in alternative paths, targets, or parameters as needed while keeping the single-line invocation style.

---

## 11. Advanced Headless Config (No UI)

| Scenario | One-Liner |
| --- | --- |
| Apply advanced defaults with UI disabled + run headless build smoke | `pwsh -NoLogo -Command "$repo=$env:BYPASS_REPO; $cfgPath=Join-Path $repo 'config.json'; $cfg=Get-Content $cfgPath -Raw | ConvertFrom-Json; if (-not ($cfg.PSObject.Properties.Name -contains 'ui')) { $cfg | Add-Member -NotePropertyName ui -NotePropertyValue (@{ enabled = $true }) }; $cfg.ui.enabled=$false; $cfg.capture.method='enhanced_capture'; $cfg.performance.monitoring=$true; $cfg.security.anti_detection.enabled=$true; $cfg | ConvertTo-Json -Depth 8 | Set-Content $cfgPath; & (Join-Path $repo 'scripts\build_windows.ps1') -SkipPrerequisites -SkipTests"` |
| Configure + build + test Release (advanced flags) | `pwsh -NoLogo -Command "Set-Location $env:BYPASS_REPO; cmake -S . -B build-advanced -G 'Visual Studio 16 2019' -A x64 -DCMAKE_BUILD_TYPE=Release -DUNDOWNUNLOCK_ENABLE_SECURITY=ON -DUNDOWNUNLOCK_ENABLE_PERF=ON; cmake --build build-advanced --config Release --parallel; ctest --test-dir build-advanced -C Release --output-on-failure"` |
| Package Release artifacts (zip/msi) | `pwsh -NoLogo -Command "Set-Location $env:BYPASS_REPO; cmake --build build-advanced --config Release --target package; $outDir=Join-Path $env:BYPASS_REPO 'artifacts'; if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }; Get-ChildItem build-advanced -Filter '*.zip' -Recurse | Copy-Item -Destination $outDir -Force"` |

---

## 12. Artifact Installation & Verification

| Action | One-Liner |
| --- | --- |
| Download + extract latest release | `pwsh -NoLogo -Command "Set-Location $env:BYPASS_REPO; $zip='$env:TEMP\undownunlock_release.zip'; iwr 'https://github.com/your-org/bypass-methods/releases/latest/download/windows-build-artifacts.zip' -OutFile $zip; Expand-Archive $zip -DestinationPath '.\artifacts\latest' -Force"` |
| Install release binaries into Program Files | `pwsh -NoLogo -Command "$src='$env:BYPASS_REPO\artifacts\latest\bin'; $dst='$env:ProgramFiles\UndownUnlock'; if (-not (Test-Path $dst)) { New-Item -ItemType Directory -Path $dst | Out-Null }; Copy-Item $src\* $dst -Recurse -Force"` |
| Verify installed version | `pwsh -NoLogo -Command "& '$env:ProgramFiles\UndownUnlock\undownunlock.exe' --version"` |
