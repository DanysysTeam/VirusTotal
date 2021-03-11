#cs Copyright
    Copyright 2021 Danysys. <hello@danysys.com>

    Licensed under the MIT license.
    See LICENSE file or go to https://opensource.org/licenses/MIT for details.
#ce Copyright

#cs Information
    Author(s)......: DanysysTeam (Danyfirex & Dany3j)
    Description....: VirusTotal UDF
    Remarks........: VirusTotal Public API 3.0 Implementation
    Version........: 1.0.0
    AutoIt Version.: 3.3.14.5
#ce Information

;~ #AutoIt3Wrapper_Au3Check_Parameters=-d -w 1 -w 2 -w 3 -w 4 -w 5 -w 6
;~ #Tidy_Parameters=/tcb=-1 /sf /ewnl /reel /gd /sfc
#Region Include
#include-once
#include "WinHttp\WinHttp.au3"
#EndRegion Include

; #CURRENT# =====================================================================================================================
; _VT_DomainGetComments
; _VT_DomainGetRelationship
; _VT_DomainGetScan
; _VT_DomainGetVotes
; _VT_DomainSetComments
; _VT_DomainSetVotes
; _VT_FileBehaviourSummary
; _VT_FileBehaviours
; _VT_FileBehavioursHtml
; _VT_FileBehavioursPCAP
; _VT_FileDownload
; _VT_FileGetComments
; _VT_FileGetDownloadUrl
; _VT_FileGetRelationship
; _VT_FileGetVotes
; _VT_FileReScanHash
; _VT_FileScan
; _VT_FileScanHash
; _VT_FileSetComments
; _VT_FileSetVotes
; _VT_FileSigmaAnalyses
; _VT_IPAddressesGetComments
; _VT_IPAddressesGetRelationship
; _VT_IPAddressesGetVotes
; _VT_IPAddressesScan
; _VT_IPAddressesSetComments
; _VT_IPAddressesSetVotes
; _VT_ResolutionScan
; _VT_SetAPIKEY
; _VT_URLGetComments
; _VT_URLGetRelationship
; _VT_URLGetScan
; _VT_URLGetVotes
; _VT_URLReScan
; _VT_URLScan
; _VT_URLSetComments
; _VT_URLSetVotes
; ===============================================================================================================================

; #INTERNAL_USE_ONLY# ===========================================================================================================
; __VT_Base64
; __VT_Base64Encode
; __VT_ReplaceValue
; __VT_WinHttpPost
; __VT__WinHttpGet
; ===============================================================================================================================

#Region Globals
Global $g__sAPIKEY = ""
;API URL
Global Const $__VT_API_VERSION = "v3"
Global Const $__VT_URL = "https://www.virustotal.com"
;Files
Global Const $__VT_PATH_FILES_UPLOAD = "/files"
Global Const $__VT_PATH_FILES_UPLOAD_URL = "/files/upload_url"
Global Const $__VT_PATH_FILES = "/files/{id}" ;SHA-256, SHA-1 or MD5 identifying the file
Global Const $__VT_PATH_FILES_ANALISE = "/files/{id}/analyse"
Global Const $__VT_PATH_FILES_COMMENTS = "/files/{id}/comments"
Global Const $__VT_PATH_FILES_VOTES = "/files/{id}/votes"
Global Const $__VT_PATH_FILES_DOWNLOAD_URL = "/files/{id}/download_url"
Global Const $__VT_PATH_FILES_DOWNLOAD = "/files/{id}/download"
Global Const $__VT_PATH_FILES_RELATIONSHIP = "/files/{id}/{relationship}"
Global Const $__VT_PATH_FILES_BEHAVIOUR_SUMMARY = "/files/{id}/behaviour_summary"
Global Const $__VT_PATH_FILES_BEHAVIOURS = "/file_behaviours/{sandbox_id}"
;sandbox_id = SHA256_SandboxName ;Sandbox Test: C2AE|SNDBOX|Sangfor ZSand|Sangfor ZSand|Sangfor ZSand|VirusTotal Cuckoofork|VirusTotal Jujubox
Global Const $__VT_PATH_FILES_BEHAVIOURS_HTML = "/file_behaviours/{sandbox_id}/html"
Global Const $__VT_PATH_FILES_BEHAVIOURS_PCAP = "/file_behaviours/{sandbox_id}/pcap"
Global Const $__VT_PATH_FILES_SIGMA_ANALISES = "/sigma_analyses/{id}"
;Urls
Global Const $__VT_PATH_URLS = "/urls"
Global Const $__VT_PATH_URL = "/urls/{id}"
Global Const $__VT_PATH_URLS_ANALISE = "/urls/{id}/analyse"
Global Const $__VT_PATH_URLS_COMMENTS = "/urls/{id}/comments"
Global Const $__VT_PATH_URLS_VOTES = "/urls/{id}/votes"
Global Const $__VT_PATH_URLS_RELATIONSHIP = "/urls/{id}/{relationship}"
;Domains
Global Const $__VT_PATH_DOMAINS = "/domains/{domain}"
Global Const $__VT_PATH_DOMAINS_COMMENTS = "/domains/{domain}/comments"
Global Const $__VT_PATH_DOMAINS_RELATIONSHIP = "/domains/{domain}/{relationship}"
Global Const $__VT_PATH_DOMAINS_VOTES = "/domains/{domain}/votes"
Global Const $__VT_PATH_RESOLUTIONS = "/resolutions/{id}"
;IP Address
Global Const $__VT_PATH_IPADDRESSES = "/ip_addresses/{ip}"
Global Const $__VT_PATH_IPADDRESSES_COMMENTS = "/ip_addresses/{ip}/comments"
Global Const $__VT_PATH_IPADDRESSES_RELATIONSHIP = "/ip_addresses/{ip}/{relationship}"
Global Const $__VT_PATH_IPADDRESSES_VOTES = "/ip_addresses/{ip}/votes"
;Analyses - No Impelemented
;Graphs - No Impelemented
;Comments - No Impelemented
;Search & Metadata - No Impelemented
#EndRegion Globals


Func _VT_SetAPIKEY($sAPIKEY)
	$g__sAPIKEY = $sAPIKEY
EndFunc   ;==>_VT_SetAPIKEY

#Region Files

Func _VT_FileBehaviours($sSandboxID)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES_BEHAVIOURS, '{sandbox_id}', $sSandboxID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_FileBehaviours

Func _VT_FileBehavioursHtml($sSandboxID)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES_BEHAVIOURS_HTML, '{sandbox_id}', $sSandboxID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_FileBehavioursHtml

Func _VT_FileBehavioursPCAP($sSandboxID)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES_BEHAVIOURS_PCAP, '{sandbox_id}', $sSandboxID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_FileBehavioursPCAP

Func _VT_FileBehaviourSummary($sID)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES_BEHAVIOUR_SUMMARY, '{id}', $sID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_FileBehaviourSummary

Func _VT_FileGetComments($sID)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES_COMMENTS, '{id}', $sID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_FileGetComments

Func _VT_FileGetRelationship($sID, $sRelationship)
	Local $sPath = __VT_ReplaceValue($__VT_PATH_FILES_RELATIONSHIP, '{id}', $sID)
	$sPath = __VT_ReplaceValue($sPath, '{relationship}', $sRelationship)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & $sPath
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_FileGetRelationship

Func _VT_FileGetVotes($sID)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES_VOTES, '{id}', $sID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_FileGetVotes

Func _VT_FileReScanHash($sID)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES_ANALISE, '{id}', $sID)
	Return __VT_WinHttpPost($sURL)
EndFunc   ;==>_VT_FileReScanHash

Func _VT_FileScan($sFilePath)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & $__VT_PATH_FILES_UPLOAD
	Local $sBoundary = StringFormat("%s%.5f", "----Boundary_VT", Random(10000, 99999))
	Local $sHeaders = "Content-Type: multipart/form-data; boundary=" & $sBoundary & @CRLF
	Local $sData = "--" & $sBoundary & @CRLF
	$sData &= __WinHttpFileContent("", "file", $sFilePath, $sBoundary)
	$sData &= "--" & $sBoundary & "--" & @CRLF
	Return __VT_WinHttpPost($sURL, StringToBinary($sData), $sHeaders)
EndFunc   ;==>_VT_FileScan

Func _VT_FileScanHash($sID)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES, '{id}', $sID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_FileScanHash

Func _VT_FileSetComments($sID, $sComment)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES_COMMENTS, '{id}', $sID)
	Local $sData = '{"data": {"type": "comment", "attributes": {"text": "' & $sComment & '"}}}'
	Return __VT_WinHttpPost($sURL, StringToBinary($sData))
EndFunc   ;==>_VT_FileSetComments

Func _VT_FileSetVotes($sID, $sVerdict)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES_VOTES, '{id}', $sID)
	Local $sData = '{"data": {"type": "vote", "attributes": {"verdict": "' & $sVerdict & '"}}}'
	Return __VT_WinHttpPost($sURL, StringToBinary($sData))
EndFunc   ;==>_VT_FileSetVotes

Func _VT_FileSigmaAnalyses($sID)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES_SIGMA_ANALISES, '{id}', $sID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_FileSigmaAnalyses

Func _VT_FileDownload($sID) ;Untested
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES_DOWNLOAD, '{id}', $sID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_FileDownload

Func _VT_FileGetDownloadUrl($sID) ;Untested
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_FILES_DOWNLOAD_URL, '{id}', $sID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_FileGetDownloadUrl
#EndRegion Files

#Region Urls


Func _VT_URLGetComments($sURLID)
	$sURLID = __VT_Base64($sURLID) ;make robust check if is id or normal url to convert to base64
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_URLS_COMMENTS, '{id}', $sURLID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_URLGetComments

Func _VT_URLGetRelationship($sURLID, $sRelationship)
	$sURLID = __VT_Base64($sURLID) ;make robust check if is id or normal url to convert to base64
	Local $sPath = __VT_ReplaceValue($__VT_PATH_URLS_RELATIONSHIP, '{id}', $sURLID)
	$sPath = __VT_ReplaceValue($sPath, '{relationship}', $sRelationship)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & $sPath
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_URLGetRelationship

Func _VT_URLGetScan($sURLID)
	$sURLID = __VT_Base64($sURLID) ;make robust check if is id or normal url to convert to base64
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_URL, '{id}', $sURLID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_URLGetScan

Func _VT_URLGetVotes($sURLID)
	$sURLID = __VT_Base64($sURLID) ;make robust check if is id or normal url to convert to base64
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_URLS_VOTES, '{id}', $sURLID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_URLGetVotes

Func _VT_URLReScan($sURLID)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_URLS_ANALISE, '{id}', __VT_Base64($sURLID))
	Return __VT_WinHttpPost($sURL, '', '')
EndFunc   ;==>_VT_URLReScan

Func _VT_URLScan($sURL)
	Local $sURLPost = $__VT_URL & "/api/" & $__VT_API_VERSION & $__VT_PATH_URLS
	Local $sBoundary = StringFormat("%s%.5f", "----Boundary_VT", Random(10000, 99999))
	Local $sHeaders = "Accept: */*" & @CRLF & "Content-Type: multipart/form-data; boundary=" & $sBoundary & @CRLF
	Local $sData = "--" & $sBoundary & @CRLF
	$sData &= 'Content-Disposition: form-data; name="url"' & @CRLF & @CRLF
	$sData &= $sURL & @CRLF
	$sData &= "--" & $sBoundary & "--" & @CRLF & @CRLF
	Return __VT_WinHttpPost($sURLPost, StringToBinary($sData), $sHeaders)
EndFunc   ;==>_VT_URLScan

Func _VT_URLSetComments($sURLID, $sComment)
	$sURLID = __VT_Base64($sURLID) ;make robust check if is id or normal url to convert to base64
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_URLS_COMMENTS, '{id}', $sURLID)
	Local $sData = '{"data": {"type": "comment", "attributes": {"text": "' & $sComment & '"}}}'
	Return __VT_WinHttpPost($sURL, StringToBinary($sData))
EndFunc   ;==>_VT_URLSetComments

Func _VT_URLSetVotes($sURLID, $sVerdict)
	$sURLID = __VT_Base64($sURLID) ;make robust check if is id or normal url to convert to base64
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_URLS_VOTES, '{id}', $sURLID)
	Local $sData = '{"data": {"type": "vote", "attributes": {"verdict": "' & $sVerdict & '"}}}'
	Return __VT_WinHttpPost($sURL, StringToBinary($sData))
EndFunc   ;==>_VT_URLSetVotes
#EndRegion Urls

#Region Domains


Func _VT_DomainGetComments($sDomain)
	$sDomain = StringReplace($sDomain, "https://", "")
	$sDomain = StringReplace($sDomain, "http://", "")
	Local $sPath = __VT_ReplaceValue($__VT_PATH_DOMAINS_COMMENTS, '{domain}', $sDomain)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & $sPath
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_DomainGetComments

Func _VT_DomainGetRelationship($sDomain, $sRelationship)
	$sDomain = StringReplace($sDomain, "https://", "")
	$sDomain = StringReplace($sDomain, "http://", "")
	Local $sPath = __VT_ReplaceValue($__VT_PATH_DOMAINS_RELATIONSHIP, '{domain}', $sDomain)
	$sPath = __VT_ReplaceValue($sPath, '{relationship}', $sRelationship)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & $sPath
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_DomainGetRelationship

Func _VT_DomainGetScan($sDomain)
	$sDomain = StringReplace($sDomain, "https://", "")
	$sDomain = StringReplace($sDomain, "http://", "")
	Local $sPath = __VT_ReplaceValue($__VT_PATH_DOMAINS, '{domain}', $sDomain)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & $sPath
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_DomainGetScan

Func _VT_DomainGetVotes($sDomain)
	$sDomain = StringReplace($sDomain, "https://", "")
	$sDomain = StringReplace($sDomain, "http://", "")
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_DOMAINS_VOTES, '{domain}', $sDomain)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_DomainGetVotes

Func _VT_DomainSetComments($sDomain, $sComment)
	$sDomain = StringReplace($sDomain, "https://", "")
	$sDomain = StringReplace($sDomain, "http://", "")
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_DOMAINS_COMMENTS, '{domain}', $sDomain)
	Local $sData = '{"data": {"type": "comment", "attributes": {"text": "' & $sComment & '"}}}'
	Return __VT_WinHttpPost($sURL, StringToBinary($sData))
EndFunc   ;==>_VT_DomainSetComments

Func _VT_DomainSetVotes($sDomain, $sVerdict)
	$sDomain = StringReplace($sDomain, "https://", "")
	$sDomain = StringReplace($sDomain, "http://", "")
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_DOMAINS_VOTES, '{domain}', $sDomain)
	Local $sData = '{"data": {"type": "vote", "attributes": {"verdict": "' & $sVerdict & '"}}}'
	Return __VT_WinHttpPost($sURL, StringToBinary($sData))
EndFunc   ;==>_VT_DomainSetVotes
#EndRegion Domains

#Region Resolution


Func _VT_ResolutionScan($sID)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_RESOLUTIONS, '{id}', $sID)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_ResolutionScan
#EndRegion Resolution

#Region IP Addresses


Func _VT_IPAddressesGetComments($sIP)
	Local $sPath = __VT_ReplaceValue($__VT_PATH_IPADDRESSES_COMMENTS, '{ip}', $sIP)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & $sPath
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_IPAddressesGetComments

Func _VT_IPAddressesGetRelationship($sIP, $sRelationship)
	Local $sPath = __VT_ReplaceValue($__VT_PATH_IPADDRESSES_RELATIONSHIP, '{ip}', $sIP)
	$sPath = __VT_ReplaceValue($sPath, '{relationship}', $sRelationship)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & $sPath
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_IPAddressesGetRelationship

Func _VT_IPAddressesGetVotes($sIP)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_IPADDRESSES_VOTES, '{ip}', $sIP)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_IPAddressesGetVotes

Func _VT_IPAddressesScan($sIP)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_IPADDRESSES, '{ip}', $sIP)
	Return __VT__WinHttpGet($sURL)
EndFunc   ;==>_VT_IPAddressesScan

Func _VT_IPAddressesSetComments($sIP, $sComment)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_IPADDRESSES_COMMENTS, '{ip}', $sIP)
	Local $sData = '{"data": {"type": "comment", "attributes": {"text": "' & $sComment & '"}}}'
	Return __VT_WinHttpPost($sURL, StringToBinary($sData))
EndFunc   ;==>_VT_IPAddressesSetComments

Func _VT_IPAddressesSetVotes($sIP, $sVerdict)
	Local $sURL = $__VT_URL & "/api/" & $__VT_API_VERSION & __VT_ReplaceValue($__VT_PATH_IPADDRESSES_VOTES, '{ip}', $sIP)
	Local $sData = '{"data": {"type": "vote", "attributes": {"verdict": "' & $sVerdict & '"}}}'
	Return __VT_WinHttpPost($sURL, StringToBinary($sData))
EndFunc   ;==>_VT_IPAddressesSetVotes
#EndRegion IP Addresses

#Region Analyses - Submissions - Operations
;no implemented
#EndRegion Analyses - Submissions - Operations

#Region Utils

Func __VT_Base64($sURL)
	$sURL = StringLower($sURL)
	Local $sEncodeURL = __VT_Base64Encode($sURL)
	Return StringStripWS(StringReplace($sEncodeURL, "=", ""), 8)
EndFunc   ;==>__VT_Base64

Func __VT_Base64Encode($input)

	$input = Binary($input)

	Local $struct = DllStructCreate("byte[" & BinaryLen($input) & "]")

	DllStructSetData($struct, 1, $input)

	Local $strc = DllStructCreate("int")

	Local $a_Call = DllCall("Crypt32.dll", "int", "CryptBinaryToString", _
			"ptr", DllStructGetPtr($struct), _
			"int", DllStructGetSize($struct), _
			"int", 1, _
			"ptr", 0, _
			"ptr", DllStructGetPtr($strc))

	If @error Or Not $a_Call[0] Then
		Return SetError(1, 0, "") ; error calculating the length of the buffer needed
	EndIf

	Local $a = DllStructCreate("char[" & DllStructGetData($strc, 1) & "]")

	$a_Call = DllCall("Crypt32.dll", "int", "CryptBinaryToString", _
			"ptr", DllStructGetPtr($struct), _
			"int", DllStructGetSize($struct), _
			"int", 1, _
			"ptr", DllStructGetPtr($a), _
			"ptr", DllStructGetPtr($strc))

	If @error Or Not $a_Call[0] Then
		Return SetError(2, 0, "") ; error encoding
	EndIf

	Return DllStructGetData($a, 1)

EndFunc   ;==>__VT_Base64Encode

Func __VT_ReplaceValue($sPath, $sValue, $sID)
	Return StringReplace($sPath, $sValue, $sID)
EndFunc   ;==>__VT_ReplaceValue
#EndRegion Utils

#Region WinHTTP POST - GET

Func __VT__WinHttpGet($sURL)
	Local Const $sAdditionalHeader = "x-apikey: " & $g__sAPIKEY
	Local $aURLParts = _WinHttpCrackUrl($sURL)
	Local $sURI = $aURLParts[0] & "://" & $aURLParts[2] ;Get Base URI
	Local $sPath = $aURLParts[6] & $aURLParts[7] ;Get Endpoint Path
	; Initialize and get session handle
	Local $hOpen = _WinHttpOpen()
	; Get connection handle
	Local $hConnect = _WinHttpConnect($hOpen, $sURI)
;~ 	ConsoleWrite("hConnect: " & $hConnect & @CRLF)
	; Make a SimpleSSL request
	Local $hRequestSSL = _WinHttpSimpleSendSSLRequest($hConnect, "GET", $sPath, Default, Default, $sAdditionalHeader)
;~ 	ConsoleWrite("hRequestSSL: " & $hRequestSSL & @CRLF)
	; Read...
	Local $sReturned = _WinHttpSimpleReadData($hRequestSSL)
	; Close handles
	_WinHttpCloseHandle($hRequestSSL)
	_WinHttpCloseHandle($hConnect)
	_WinHttpCloseHandle($hOpen)

	Return $sReturned
EndFunc   ;==>__VT__WinHttpGet

Func __VT_WinHttpPost($sURL, $sData = '', $sHeaders = '', $iTimeouts = 60000)
	Local Const $sAdditionalHeader = "x-apikey: " & $g__sAPIKEY & @CRLF & $sHeaders
	Local $aURLParts = _WinHttpCrackUrl($sURL)
	Local $sURI = $aURLParts[0] & "://" & $aURLParts[2] ;Get Base URI
	Local $sPath = $aURLParts[6] & $aURLParts[7] ;Get Endpoint Path
	; Initialize and get session handle
	Local $hOpen = _WinHttpOpen()
	_WinHttpSetTimeouts($hOpen, 0, $iTimeouts, $iTimeouts, $iTimeouts)
	; Get connection handle
	Local $hConnect = _WinHttpConnect($hOpen, $sURI)
;~ 	ConsoleWrite("hConnect: " & $hConnect & @CRLF)
	; Make a SimpleSSL request
	Local $hRequestSSL = _WinHttpSimpleSendSSLRequest($hConnect, "POST", $sPath, Default, $sData, $sAdditionalHeader)
;~ 	ConsoleWrite("hRequestSSL: " & $hRequestSSL & @CRLF)
	; Read...
	Local $sReturned = _WinHttpSimpleReadData($hRequestSSL)
	; Close handles
	_WinHttpCloseHandle($hRequestSSL)
	_WinHttpCloseHandle($hConnect)
	_WinHttpCloseHandle($hOpen)
	Return $sReturned
EndFunc   ;==>__VT_WinHttpPost
#EndRegion WinHTTP POST - GET

