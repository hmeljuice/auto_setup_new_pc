if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

#function Check-Command($cmdname) {
#    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
#}

# -----------------------------------------------------------------------------
$computerName = Read-Host 'Vnesi novo ime za PC'
Write-Host "Ime PC-a bo: " $computerName  -ForegroundColor Yellow
Rename-Computer -NewName $computerName
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Disable Sleep on AC Power..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Powercfg /Change monitor-timeout-ac 20
Powercfg /Change standby-timeout-ac 0
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Change Date Format" -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Set-ItemProperty -Path "HKCU:\Control Panel\International" -name sShortDate -value "d.MM.yyyy"
# -----------------------------------------------------------------------------
#Write-Host ""
#Write-Host "Add 'This PC' Desktop Icon..." -ForegroundColor Green
#Write-Host "------------------------------------" -ForegroundColor Green
#$thisPCIconRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
#$thisPCRegValname = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" 
#$item = Get-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -ErrorAction SilentlyContinue 
#if ($item) { 
#    Set-ItemProperty  -Path $thisPCIconRegPath -name $thisPCRegValname -Value 0  
#} 
#else { 
#    New-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -Value 0 -PropertyType DWORD | Out-Null  
#} 

# To list all appx packages:
# Get-AppxPackage | Format-Table -Property Name,Version,PackageFullName
Write-Host "Removing default Rubbish..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$uwpRubbishApps = @(
    "Microsoft.Messaging",
    "king.com.CandyCrushSaga",
    "Microsoft.BingNews",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.People",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.YourPhone",
    "Microsoft.MicrosoftOfficeHub",
    "Fitbit.FitbitCoach",
    "4DF9E0F8.Netflix",
    "Microsoft.GetHelp")

foreach ($uwp in $uwpRubbishApps) {
    Get-AppxPackage -Name $uwp | Remove-AppxPackage
}
# -----------------------------------------------------------------------------
#Write-Host ""
#Write-Host "Starting UWP apps to upgrade..." -ForegroundColor Green
#Write-Host "------------------------------------" -ForegroundColor Green
#$namespaceName = "root\cimv2\mdm\dmmap"
#$className = "MDM_EnterpriseModernAppManagement_AppManagement01"
#$wmiObj = Get-WmiObject -Namespace $namespaceName -Class $className
#$result = $wmiObj.UpdateScanMethod()
# -----------------------------------------------------------------------------
#Write-Host ""
#Write-Host "Installing IIS..." -ForegroundColor Green
#Write-Host "------------------------------------" -ForegroundColor Green
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-DefaultDocument -All
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionDynamic -All
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic -All
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebSockets -All
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationInit -All
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45 -All
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ServerSideIncludes
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-BasicAuthentication
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication
# -----------------------------------------------------------------------------
#Write-Host ""
#Write-Host "Enable Windows 10 Developer Mode..." -ForegroundColor Green
#Write-Host "------------------------------------" -ForegroundColor Green
#reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowDevelopmentWithoutDevLicense" /d "1"
# -----------------------------------------------------------------------------
#Write-Host ""
#Write-Host "Enable Remote Desktop..." -ForegroundColor Green
#Write-Host "------------------------------------" -ForegroundColor Green
#Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 0
#Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "UserAuthentication" -Value 1
#Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

#if (Check-Command -cmdname 'choco') {
#    Write-Host "Choco is already installed, skip installation."
#}
#else {
Write-Host ""
Write-Host "Installing Chocolate for Windows..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
#}

Write-Host ""
Write-Host "Installing Applications..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
#Write-Host "[WARN] Ma de in China: some software like Google Chrome require the true Internet first" -ForegroundColor Yellow

$Apps = @(
    #    "7zip.install",
    #    "git",
    "googlechrome",
    #    "vlc",
    #    "ffmpeg",
    #    "vscode",
    #    "sysinternals",
    #    "notepadplusplus.install",
    #    "linqpad",
    #    "postman",
    #    "nuget.commandline",
    #    "beyondcompare",
    #    "filezilla",
    #    "microsoft-teams.install",
    #    "github-desktop",
    #    "irfanview",
    #    "nodejs-lts",
    #    "azure-cli",
    #    "powershell-core",
    #    "chocolateygui",
    #    "obs-studio"
    "naps2",
    "totalcommander",
    "teamviewer"
)

foreach ($app in $Apps) {
    choco install $app -y
}

Write-Host "Setting up Birokrat-Gonilniki..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$source = 'https://http://www.birokrat.si/media/sistemska-podpora/Gonilnik-Birokrat.exe'
$destination = 'C:\birokratGonilnik\Gonilnik-Birokrat.exe'
Invoke-WebRequest -Uri $source -OutFile $destination
Start-Process -Wait -FilePath "C:\birokratGonilnik\Gonilnik-Birokrat.exe" -ArgumentList "/S" -PassThru

#Write-Host "Setting up Git for Windows..." -ForegroundColor Green
#Write-Host "------------------------------------" -ForegroundColor Green
#git config --global user.email "edi.wang@outlook.com"
#git config --global user.name "Edi Wang"
#git config --global core.autocrlf true

Write-Host "Setting up dotnet for Windows..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
[Environment]::SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development", "Machine")
[Environment]::SetEnvironmentVariable("DOTNET_PRINT_TELEMETRY_MESSAGE", "false", "Machine")
[Environment]::SetEnvironmentVariable("DOTNET_CLI_TELEMETRY_OPTOUT", "1", "Machine")
dotnet tool install --global dotnet-ef
dotnet tool update --global dotnet-ef

#Write-Host "Enabling Chinese input method..." -ForegroundColor Green
#Write-Host "------------------------------------" -ForegroundColor Green
#$LanguageList = Get-WinUserLanguageList
#$LanguageList.Add("zh-CN")
#Set-WinUserLanguageList $LanguageList -Force

Write-Host "Applying file explorer settings..." -ForegroundColor Green
cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f"
cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v AutoCheckSelect /t REG_DWORD /d 0 /f"
cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v LaunchTo /t REG_DWORD /d 1 /f"

#Write-Host "Setting Time zone..." -ForegroundColor Green
#Set-TimeZone -Name "China Standard Time"

#Write-Host "Installing Github.com/microsoft/artifacts-credprovider..." -ForegroundColor Green
#Write-Host "------------------------------------" -ForegroundColor Green
#iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/microsoft/artifacts-credprovider/master/helpers/installcredprovider.ps1'))

#Write-Host "Removing Bluetooth icons..." -ForegroundColor Green
#Write-Host "------------------------------------" -ForegroundColor Green
#cmd.exe /c "reg add `"HKCU\Control Panel\Bluetooth`" /v `"Notification Area Icon`" /t REG_DWORD /d 0 /f"

# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Checking Windows updates..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Install-Module -Name PSWindowsUpdate -Force
Write-Host "Installing updates... (Computer will reboot in minutes...)" -ForegroundColor Green
Get-WindowsUpdate -AcceptAll -Install -ForceInstall -AutoReboot

# -----------------------------------------------------------------------------
Write-Host "------------------------------------" -ForegroundColor Green
Read-Host -Prompt "Setup is done, restart is needed, press [ENTER] to restart computer."
Restart-Computer

# Happy working! From Blaž :-) Contact: strlekar.blaz@gmail.com