; (UTF-8 with a byte order mark, which NSIS needs for the Dutch text.)
; Added to the Windows setup that `dx bundle` makes (Dioxus.toml:
; [bundle.windows.nsis] installer_hooks).
;
; Up to 1.7.0 releases also came as an .msi, which installs 2Secret for
; everyone on the PC in Program Files. This setup installs it for the user
; and can update itself; the two do not replace each other, so having both
; meant two copies of 2Secret. When the .msi version is installed, the setup
; offers to remove it (Windows asks for permission), so one 2Secret is left.
; The vault is not part of either installation (%APPDATA%\2Secret).

; The .msi's UpgradeCode, the same for every version.
!define TWOSECRET_MSI_UPGRADE_CODE "{C818A99A-75BE-5470-AD1B-166F666DF857}"

Function .onInit
    ; The product code of an installed .msi version, if there is one.
    System::Call 'msi::MsiEnumRelatedProductsW(w "${TWOSECRET_MSI_UPGRADE_CODE}", i 0, i 0, w .r1) i .r0'
    IntCmp $0 0 0 done done
    ; Updates from within the app run silently and only update this setup's
    ; installation: they leave the .msi version alone.
    IfSilent done
    ; Dutch (Netherlands, Belgium) or English, like the app.
    System::Call 'kernel32::GetUserDefaultUILanguage() i .r3'
    IntOp $3 $3 & 0x3FF
    IntCmp $3 0x13 dutch
    MessageBox MB_YESNO|MB_ICONQUESTION "2Secret is also installed for everyone on this PC (the .msi version).$\r$\n$\r$\nRemove that one, so only this 2Secret is left? Your vault stays where it is. Windows asks for permission." IDNO done
    Goto remove
  dutch:
    MessageBox MB_YESNO|MB_ICONQUESTION "2Secret is ook geïnstalleerd voor iedereen op deze pc (de .msi-versie).$\r$\n$\r$\nDie verwijderen, zodat alleen deze 2Secret overblijft? Je kluis blijft staan. Windows vraagt om toestemming." IDNO done
  remove:
    ExecWait '"$SYSDIR\msiexec.exe" /x $1 /qb'
  done:
FunctionEnd

; Passkeys in Windows 11 (crates/app/src/windows_passkeys.rs): the signed
; identity package and the logos it names, in releases built with a signing
; certificate (scripts/windows-identity-package.ps1 writes the package
; before `dx bundle`). Without it the setup is as before. 2Secret registers
; the package itself, when the person turns the feature on.
!if /FileExists "${__FILEDIR__}\identity\2Secret-identity.msix"
Section "-PasskeysInWindows"
    SetOutPath "$INSTDIR"
    File "${__FILEDIR__}\identity\2Secret-identity.msix"
    SetOutPath "$INSTDIR\Assets"
    File "${__FILEDIR__}\identity\Assets\*.png"
    SetOutPath "$INSTDIR"
SectionEnd
!endif

; The registered identity package points at the folder that is gone now.
; Nothing happens when it was never registered.
Function un.onUninstSuccess
    ${If} ${RunningX64}
        StrCpy $0 "$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
    ${Else}
        StrCpy $0 "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe"
    ${EndIf}
    nsExec::Exec '"$0" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-AppxPackage -Name io.github.joostiphone.twosecret | Remove-AppxPackage"'
    Pop $1
FunctionEnd
