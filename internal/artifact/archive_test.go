package artifact

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func testArchive(body []byte, name string) []byte {
	data := []byte("!<arch>\n" + fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name, 0, 0, 0, 0644, len(body)))
	data = append(data, body...)
	if len(body)&1 != 0 {
		data = append(data, '\n')
	}
	return data
}

func TestNativeObjectTargets(t *testing.T) {
	elf := make([]byte, 64)
	copy(elf, "\x7fELF")
	elf[4], elf[5] = 2, 1
	binary.LittleEndian.PutUint16(elf[18:20], 183)
	if err := verifyArchive(testArchive(elf, "arm.o/"), "aarch64-unknown-linux-gnu"); err != nil {
		t.Fatal(err)
	}
	if err := verifyArchive(testArchive(elf, "arm.o/"), testTarget); err == nil {
		t.Fatal("accepted ARM object as amd64")
	}
	mach := make([]byte, 32)
	binary.LittleEndian.PutUint32(mach, 0xfeedfacf)
	binary.LittleEndian.PutUint32(mach[4:], 0x0100000c)
	if err := verifyArchive(testArchive(mach, "arm.o/"), "aarch64-apple-darwin"); err != nil {
		t.Fatal(err)
	}
	if err := verifyArchive(testArchive(mach, "arm.o/"), testTarget); err == nil {
		t.Fatal("accepted Mach-O as Linux")
	}
	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff, 0x8664)
	if err := verifyArchive(testArchive(coff, "win.o/"), testTarget); err == nil {
		t.Fatal("accepted Windows object as Linux")
	}
	bsd := append([]byte("test.o"), mach...)
	if err := verifyArchive(testArchive(bsd, "#1/6"), "aarch64-apple-darwin"); err != nil {
		t.Fatal(err)
	}
}

func TestRejectMalformedNativeArchives(t *testing.T) {
	malformed := map[string][]byte{
		"magic":            []byte("not an archive"),
		"truncated header": []byte("!<arch>\nshort"),
		"no objects":       testArchive([]byte("symbols"), "/"),
		"invalid BSD name": testArchive([]byte("x"), "#1/a"),
		"large BSD name":   testArchive([]byte("x"), "#1/9"),
	}
	wrongHeader := testArchive([]byte("x"), "test.o/")
	wrongHeader[8+58] = 'x'
	malformed["header trailer"] = wrongHeader
	wrongLength := testArchive([]byte("x"), "test.o/")
	copy(wrongLength[8+48:8+58], "9999999999")
	malformed["member overflow"] = wrongLength
	negative := testArchive([]byte("x"), "test.o/")
	copy(negative[8+48:8+58], "-1        ")
	malformed["negative length"] = negative
	for name, body := range malformed {
		t.Run(name, func(t *testing.T) {
			if err := verifyArchive(body, testTarget); err == nil {
				t.Fatal("accepted malformed archive")
			}
		})
	}
}
