package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

type MZHeader struct {
	Signature    uint16
	LastPageSize uint16
	Pages        uint16
	Relocations  uint16
	HeaderSize   uint16
	MinAlloc     uint16
	MaxAlloc     uint16
	InitialSS    uint16
	InitialSP    uint16
	Checksum     uint16
	InitialIP    uint16
	InitialCS    uint16
	RelocAddr    uint16
	OverlayNum   uint16
	Reserved     [8]uint16
	OEMID        uint16
	OEMInfo      uint16
	Reserved2    [20]uint16
	PEHeaderAddr uint32
}

type PEHeader struct {
	Signature            uint32
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type PESectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

func findPEOffset(data []byte, pos int) int {
	minPeOffset := 0x40
	maxPeOffset := 0x200

	for offset := minPeOffset; offset <= maxPeOffset; offset++ {
		if pos+offset+4 > len(data) {
			break
		}
		if bytes.Equal(data[pos+offset:pos+offset+4], []byte{0x50, 0x45, 0x00, 0x00}) {
			return offset
		}
	}

	return -1
}

func findMZHeaders(buffer []byte) []int {
	dosMagic := []byte("MZ")
	mzPositions := []int{}

	for pos := 0; pos < len(buffer)-len(dosMagic); pos++ {
		if bytes.Equal(buffer[pos:pos+len(dosMagic)], dosMagic) {
			mzPositions = append(mzPositions, pos)
		}
	}

	return mzPositions
}

func extractExecutables(inputPath, outputPath string) {
	data, err := ioutil.ReadFile(inputPath)
	if err != nil {
		log.Fatalf("Failed to read input file: %v", err)
	}

	mzOffsets := findMZHeaders(data)

	count := 0
	headers := make(map[string]bool)

	for _, pos := range mzOffsets {
		peHeaderAddr := int(binary.LittleEndian.Uint32(data[pos+0x3C : pos+0x3C+4]))
		peHeaderPos := pos + peHeaderAddr

		if peHeaderAddr <= 0 || peHeaderPos >= len(data) || peHeaderPos+4 > len(data) {
			continue
		}

		if bytes.Equal(data[peHeaderPos:peHeaderPos+4], []byte{0x50, 0x45, 0x00, 0x00}) {
			peMachine := binary.LittleEndian.Uint16(data[peHeaderPos+4 : peHeaderPos+4+2])

			if peMachine == 0x14c || peMachine == 0x8664 {
				peSize := binary.LittleEndian.Uint32(data[peHeaderPos+0x50 : peHeaderPos+0x50+4])
				fileAlignment := binary.LittleEndian.Uint32(data[peHeaderPos+0x3C : peHeaderPos+0x3C+4])

				if peSize != 0 && peHeaderPos+int(peSize) <= len(data) && peSize <= 100000000 {
					headerStr := string(data[peHeaderPos : peHeaderPos+min(1024, int(peSize))])

					if _, found := headers[headerStr]; !found {
						headers[headerStr] = true

						padding := 0
						if fileAlignment != 0 && int(peSize)%int(fileAlignment) != 0 {
							padding = int(fileAlignment) - int(peSize)%int(fileAlignment)
						}

						extractedSize := int(peSize) + padding
						if peHeaderPos+extractedSize <= len(data) {
							filename := fmt.Sprintf("%s%d.exe", outputPath, count)
							count++

							err = ioutil.WriteFile(filename, data[pos:pos+extractedSize], 0644)
							if err != nil {
								log.Printf("Failed to write output file: %v", err)
							} else {
								fmt.Printf("Extracted file: %s\n", filename)
							}
						}
					}
				}
			}
		}
	}

	if count == 0 {
		fmt.Println("No executables found in input file.")
	} else {
		fmt.Printf("Extracted %d executables to output path: %s\n", count, outputPath)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <input_file> <output_dir>\n", os.Args[0])
		return
	}

	inputPath := os.Args[1]
	outputPath := os.Args[2]

	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		fmt.Println("Input file does not exist:", inputPath)
		return
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		err := os.Mkdir(outputPath, 0755)
		if err != nil {
			fmt.Println("Failed to create output directory:", outputPath)
			return
		}
	} else if info, err := os.Stat(outputPath); err == nil && !info.IsDir() {
		fmt.Println("Output path is not a directory:", outputPath)
		return
	}

	extractExecutables(inputPath, outputPath)
}
