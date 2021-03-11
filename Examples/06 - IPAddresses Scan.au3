#include "..\VirusTotal.au3"


_Example()

Func _Example()

	_VT_SetAPIKEY("YOUR_APIKEY")

	Local $sJson = _VT_IPAddressesScan("8.8.8.8")
	ConsoleWrite($sJson & @CRLF)

EndFunc   ;==>_Example
