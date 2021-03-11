# VirusTotal AutoIt

[![Latest Version](https://img.shields.io/badge/Latest-v1.0.0-green.svg)]()
[![MIT License](https://img.shields.io/github/license/mashape/apistatus.svg)]()
[![Made with Love](https://img.shields.io/badge/Made%20with-%E2%9D%A4-red.svg?colorB=11a9f7)]()


VirusTotal public API 3.0 Implementation in AutoIt


## Features
* Files Endpoint.
* URLs Endpoint.
* Domains Endpoint.
* IP Addresses Endpoint.


## Usage

## Basic Usage

##### Scan File Hash:
```autoit
#include "..\VirusTotal.au3"


_Example()

Func _Example()

	_VT_SetAPIKEY("YOUR_APIKEY")

	Local $sJson = _VT_FileScanHash("0FA7CE72C5E772F87B0E2E1EAB8CCD177344220A")
	ConsoleWrite($sJson & @CRLF)
	
EndFunc   ;==>_Example

```

##### More examples [here.](/Examples)

## Release History
See [CHANGELOG.md](CHANGELOG.md)


<!-- ## Acknowledgments & Credits -->


## License

Usage is provided under the [MIT](https://choosealicense.com/licenses/mit/) License.

Copyright © 2021, [Danysys.](https://www.danysys.com)