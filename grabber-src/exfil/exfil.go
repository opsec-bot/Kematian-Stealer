package exfil

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
)

func PrintStuff(filename string, stuff string) {
	if stuff == "" {
		stuff = "No data"
	}

	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	gzipWriter.Write([]byte(stuff))
	gzipWriter.Close()

	encodedBase64 := base64.StdEncoding.EncodeToString(compressed.Bytes())

	fmt.Println(filename + "\n" + encodedBase64)
}
