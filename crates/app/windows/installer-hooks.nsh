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
