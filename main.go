package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/mholt/archiver/v3"
)

type IOC struct {
	Value  string
	Type   string
	Offset int64
}

var (
	validTLDs     = `(?:com|net|org|edu|gov|mil|biz|ru|pk|kp|ir|xyz|top|online|ml|us|buzz|tk|cf|ga|zip|cn|mov|sbs|info|name|museum|coop|aero|[a-z]{2})` //included some valid TLDs
	ipPattern     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	domainPattern = regexp.MustCompile(`\b([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+` + validTLDs + `\b`) //domain pattern with valid TLDs and  hostname validation
	urlPattern    = regexp.MustCompile(
		`\b(?:https?|ftp|sftp)://` + //common protocols
			`(?:` + //start of the host group
			`(?:\d{1,3}\.){3}\d{1,3}|` + //IP
			`(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+` + validTLDs + //domain
			`)` +
			`(?::\d{1,5})?` + //an optional port
			`(?:/[^\s]*)?` + //for the path
			`\b`,
	)
	registryPattern = regexp.MustCompile(`\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_USERS|HKU|HKEY_CLASSES_ROOT|HKCR)\\[\\w-]+\b`)
)

func main() {
	myApp := app.New()
	window := myApp.NewWindow("GoStractor")
	//these next two lines are the entry widgets. The first one is the input entry widget, and the second one is the output entry widget.
	inputEntry := widget.NewEntry()
	outputEntry := widget.NewEntry()
	//this is the info label widget to explain that the app accepts any type and always saves in CSV format.
	infoLabel := widget.NewLabel("GoStractor accepts any file type for IOC extraction, this includes non-standard defanged filetypes.\nResults will always be saved in CSV format.")
	infoLabel.Wrapping = fyne.TextWrapWord
	inputButton := widget.NewButton("Select File", func() { //this selects the input file (ANY SUPPORTED)
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if reader == nil {
				return
			}
			inputEntry.SetText(reader.URI().Path())
		}, window)
		fd.Resize(fyne.NewSize(800, 800))
		fd.Show()
	})

	outputButton := widget.NewButton("Select Output", func() { //this selects the output file (CSV)
		fd := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if writer == nil {
				return
			}
			outputEntry.SetText(writer.URI().Path())
		}, window)
		fd.Resize(fyne.NewSize(800, 800))
		fd.Show()
	})

	// Process button
	processButton := widget.NewButton("Extract IOCs", func() {
		go processFile(inputEntry.Text, outputEntry.Text, window)
		window.Resize(fyne.Size{Width: 500, Height: 500}) //this ensures the window is big enough to show the dialog

	})
	processButton.Importance = widget.HighImportance

	// Layout
	content := container.NewVBox(
		infoLabel,
		container.NewHBox(inputEntry, inputButton),
		container.NewHBox(outputEntry, outputButton),
		processButton,
	)

	window.SetContent(content)
	window.Resize(fyne.NewSize(500, 200))
	window.ShowAndRun()
}
func processFile(inputPath, outputPath string, window fyne.Window) {
	//This processes .zip and .7z archives and extracts them to a temporary directory.
	ext := filepath.Ext(inputPath)
	if ext == ".zip" || ext == ".7z" {
		tempDir, err := os.MkdirTemp("", "gostractor_*")
		if err != nil {
			dialog.ShowError(err, window)
			return
		}
		defer os.RemoveAll(tempDir)

		//This extracts the input file to a temporary directory.
		err = archiver.Extract(inputPath, tempDir, "")
		if err != nil {
			dialog.ShowError(err, window)
			return
		}
		inputPath = tempDir
	}

	iocs := []IOC{}
	//these are self explanatory
	hash, err := calculateSHA256(inputPath)
	if err != nil {
		dialog.ShowError(err, window)
		return
	}
	iocs = append(iocs, IOC{Value: hash, Type: "SHA-256", Offset: 0})

	if err := extractIOCs(inputPath, &iocs); err != nil {
		dialog.ShowError(err, window)
		return
	}

	if err := writeCSV(outputPath, iocs); err != nil {
		dialog.ShowError(err, window)
		return
	}

	dialog.ShowInformation("Success", "IOCs extracted successfully", window)
}
func calculateSHA256(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func extractIOCs(filename string, iocs *[]IOC) error { //Extracts IOCs from the input file.
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	offset := int64(0)
	buffer := make([]byte, 4096)

	for {
		n, err := reader.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		str := string(buffer[:n])

		for _, match := range ipPattern.FindAllString(str, -1) {
			*iocs = append(*iocs, IOC{Value: match, Type: "IP", Offset: offset}) //Appends the IP to the IOCs list.
		}

		for _, match := range domainPattern.FindAllString(str, -1) {
			*iocs = append(*iocs, IOC{Value: match, Type: "Domain", Offset: offset}) //Appends the domain to the IOCs list.
		}

		for _, match := range urlPattern.FindAllString(str, -1) {
			*iocs = append(*iocs, IOC{Value: match, Type: "URL", Offset: offset}) //Appends the URL to the IOCs list.
		}

		for _, match := range registryPattern.FindAllString(str, -1) {
			*iocs = append(*iocs, IOC{Value: match, Type: "Registry", Offset: offset}) //Appends the Registry to the IOCs list.
		}

		offset += int64(n)
	}

	return nil
}

func writeCSV(filename string, iocs []IOC) error { //Writes the extracted IOCs to a CSV file.
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"IOC", "Type", "Offset"}); err != nil {
		return err
	}

	for _, ioc := range iocs {
		if err := writer.Write([]string{ioc.Value, ioc.Type, fmt.Sprintf("%d", ioc.Offset)}); err != nil {
			return err
		}
	}

	return nil
}
