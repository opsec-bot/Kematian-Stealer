package batch

import (
	"io"
	"net/http"
	"os"
	"os/exec"
)

func ObfuscateCode(file string) error {
	somalifuscatorPath, err := downloadSomalifuscatorV2()
	if err != nil {
		return err
	}

	//run somalifuscator aginst the file
	cmd := exec.Command(somalifuscatorPath, "-f", file)
	cmd.Run()

	//remove the original file
	err = os.Remove(file)
	if err != nil {
		return err
	}

	err = os.Remove(somalifuscatorPath)
	if err != nil {
		return err
	}

	err = os.Rename("output_obf.bat", "output.bat")
	if err != nil {
		return err
	}
	return nil
}

func downloadSomalifuscatorV2() (string, error) {
	var url string = "https://github.com/KDot227/SomalifuscatorV2/releases/download/AutoBuild/main.exe"
	var somaliString string = "somalifuscator.exe"

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	//place the exe in the same directory as the builder
	out, err := os.Create(somaliString)
	if err != nil {
		return "", err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	return cwd + "\\" + somaliString, nil
}
