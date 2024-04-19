package screenshot

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"syscall"
	"unsafe"
)

var (
	u32 = syscall.NewLazyDLL("user32.dll")
	g32 = syscall.NewLazyDLL("gdi32.dll")
	r   struct {
		L, T, R, B int32
	}
)

func TakeScreenshot() {
	win, _, _ := u32.NewProc("GetDesktopWindow").Call()
	dc, _, _ := u32.NewProc("GetDC").Call(win)
	defer u32.NewProc("ReleaseDC").Call(win, dc)

	u32.NewProc("GetWindowRect").Call(win, uintptr(unsafe.Pointer(&r)))
	eat := int(r.R - r.L)
	davidgoggins := int(r.B - r.T)

	cdc, _, _ := g32.NewProc("CreateCompatibleDC").Call(dc)
	defer g32.NewProc("DeleteDC").Call(cdc)

	cbmp, _, _ := g32.NewProc("CreateCompatibleBitmap").Call(dc, uintptr(eat), uintptr(davidgoggins))
	defer g32.NewProc("DeleteObject").Call(cbmp)

	g32.NewProc("SelectObject").Call(cdc, cbmp)
	g32.NewProc("BitBlt").Call(cdc, 0, 0, uintptr(eat), uintptr(davidgoggins), dc, 0, 0, 0x00CC0069)

	img := image.NewRGBA(image.Rect(0, 0, eat, davidgoggins))
	pixels := make([]uint32, eat*davidgoggins)

	g32.NewProc("GetBitmapBits").Call(cbmp, uintptr(len(pixels)*4), uintptr(unsafe.Pointer(&pixels[0])))

	for i := 0; i < len(pixels); i++ {
		cr := pixels[i]
		img.Set(i%eat, i/eat, color.RGBA{
			R: uint8(cr & 0xFF),
			G: uint8((cr >> 8) & 0xFF),
			B: uint8((cr >> 16) & 0xFF),
			A: 255,
		})
	}

	f, _ := os.Create("screenshot.png")
	defer f.Close()
	_ = png.Encode(f, img)
}
