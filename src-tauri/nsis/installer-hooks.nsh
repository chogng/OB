!macro NSIS_HOOK_PREUNINSTALL
  ; Best-effort cleanup for legacy versions that registered a custom
  ; protocol handler (`appointer-origin://...`).

  SetRegView 64
  DeleteRegKey HKCU "Software\\Classes\\appointer-origin"
  DeleteRegKey HKLM "Software\\Classes\\appointer-origin"

  SetRegView 32
  DeleteRegKey HKCU "Software\\Classes\\appointer-origin"
  DeleteRegKey HKLM "Software\\Classes\\appointer-origin"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Local ZIP mode: no custom protocol registration.
  ; Best-effort cleanup for upgrades (remove legacy protocol keys).

  SetRegView 64
  DeleteRegKey HKCU "Software\\Classes\\appointer-origin"

  SetRegView 32
  DeleteRegKey HKCU "Software\\Classes\\appointer-origin"
!macroend
