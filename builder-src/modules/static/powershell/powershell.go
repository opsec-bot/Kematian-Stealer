package powershell

import (
	"archive/zip"
	"io"
	"net/http"
	"os"
)

func GetObfuscator() string {
	obfuscatorUrl := "https://github.com/KDot227/Somalifuscator-Powershell-Edition/archive/refs/heads/main.zip"
	// Download obfuscator
	// Unzip obfuscator
	// Return obfuscator path
	resp, err := http.Get(obfuscatorUrl)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	//write the body to file
	out, err := os.Create("obfuscator.zip")
	if err != nil {
		panic(err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		panic(err)
	}

	// Unzip obfuscator
	zipReader, err := zip.OpenReader("obfuscator.zip")
	if err != nil {
		panic(err)
	}
	defer zipReader.Close()

	for _, file := range zipReader.Reader.File {
		fileReader, err := file.Open()
		if err != nil {
			panic(err)
		}
		defer fileReader.Close()

		// Create a new file
		newFile, err := os.Create(file.Name)
		if err != nil {
			panic(err)
		}
		defer newFile.Close()

		_, err = io.Copy(newFile, fileReader)
		if err != nil {
			panic(err)
		}
	}
	return "Somalifuscator-Powershell-Edition-main"
}
