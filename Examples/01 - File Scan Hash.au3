#include "..\VirusTotal.au3"


_Example()

Func _Example()

	_VT_SetAPIKEY("YOUR_APIKEY")

	Local $sJson = _VT_FileScanHash("0FA7CE72C5E772F87B0E2E1EAB8CCD177344220A")
	ConsoleWrite($sJson & @CRLF)

	$sJson = _VT_FileScanHash("b2da063c3a9d12edec043cc0bdb19bf12f0dfbc398f20b10d22cd510027c65fc")
	ConsoleWrite($sJson & @CRLF)

	$sJson = _VT_FileReScanHash("1abde8d5403aa3371edd73b72324444a9e19cacbec6f0b38bec2fda23b8b4445")
	ConsoleWrite($sJson & @CRLF)

	Local $sFile = @WindowsDir & "\notepad.exe"
	Local $sJson = _VT_FileScan($sFile)
	ConsoleWrite($sJson & @CRLF)

EndFunc   ;==>_Example
