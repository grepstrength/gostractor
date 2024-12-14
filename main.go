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
	"strings"
)

type IOC struct {
	Value  string
	Type   string
	Offset int64
}

var (
	validTLDs     = `(?:com|net|org|edu|gov|mil|biz|info|name|museum|coop|aero|[a-z]{2})` //included some valid TLDs
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
	if len(os.Args) < 2 {
		fmt.Println("Usage: gostractor.exe <input_file> [output_file]")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := ""

	if len(os.Args) > 2 {
		outputFile = os.Args[2]
	} else {
		outputFile = strings.TrimSuffix(inputFile, filepath.Ext(inputFile)) + "_IOCs.csv" //outputs the file name with _IOCs.csv
	}

	iocs := []IOC{}

	//Calculate SHA-256
	hash, err := calculateSHA256(inputFile)
	if err != nil {
		fmt.Printf("Error calculating SHA-256: %v\n", err)
		os.Exit(1)
	}
	iocs = append(iocs, IOC{Value: hash, Type: "SHA-256", Offset: 0}) //appends the SHA-256 hash to the iocs

	if err := extractIOCs(inputFile, &iocs); err != nil { //Extracts IOCs from the file.
		fmt.Printf("Error extracting IOCs: %v\n", err)
		os.Exit(1)
	}

	if err := writeCSV(outputFile, iocs); err != nil { //Writes the IOCs to a CSV file.
		fmt.Printf("Error writing CSV: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("IOCs have been written to %s\n", outputFile)
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

func extractIOCs(filename string, iocs *[]IOC) error { //Extracts IOCs from the file.
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

func writeCSV(filename string, iocs []IOC) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"IOC", "Type", "Offset"}); err != nil { //
		return err
	}

	for _, ioc := range iocs {
		if err := writer.Write([]string{ioc.Value, ioc.Type, fmt.Sprintf("%d", ioc.Offset)}); err != nil { //
			return err
		}
	}

	return nil
}
