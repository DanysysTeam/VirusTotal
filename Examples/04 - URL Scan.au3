#include "..\VirusTotal.au3"


_Example()

Func _Example()

	_VT_SetAPIKEY("YOUR_APIKEY")

	Local $sJson = _VT_URLScan("https://www.google.com")
	ConsoleWrite($sJson & @CRLF)

    $sJson = _VT_URLGetScan("https://www.google.com")
	ConsoleWrite($sJson & @CRLF)

EndFunc   ;==>_Example
