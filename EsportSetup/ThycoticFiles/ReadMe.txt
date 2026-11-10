

cd C:\DelineaPMTest\


\\\\Clean only - this will only clean all traces of delinea off the device
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Really_Purge_Delinea_v4_Fixed_Restart_Revised.ps1 -ClearCcmCache




\\\\\\\ Clean and Install the new version.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Really_Purge_Delinea_v4_Fixed_Restart_Revised.ps1 -Install -ServerUrl "https://dallasisd.privilegemanagercloud.com/TMS/" -InstallCode "ZC6U-3BRY-FR8Y"


\\\If it fails in any of the phases, add pass -IgnorePendingRestart
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Really_Purge_Delinea_v4_Fixed_Restart_Revised.ps1 -Install -ServerUrl "https://dallasisd.privilegemanagercloud.com/TMS/" -InstallCode "ZC6U-3BRY-FR8Y" pass -IgnorePendingRestart

