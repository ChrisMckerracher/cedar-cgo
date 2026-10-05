package artifact

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// verifyArchive checks real object headers instead of trusting the target label.
func verifyArchive(archive []byte, target string) error {
	if !bytes.HasPrefix(archive, []byte("!<arch>\n")) {
		return fmt.Errorf("native library is not an archive")
	}
	objects := 0
	for offset := 8; offset < len(archive); {
		if len(archive)-offset < 60 {
			return fmt.Errorf("truncated native archive header")
		}
		header := archive[offset : offset+60]
		if string(header[58:]) != "`\n" {
			return fmt.Errorf("invalid native archive header")
		}
		size, err := strconv.Atoi(strings.TrimSpace(string(header[48:58])))
		offset += 60
		if err != nil || size < 0 || size > len(archive)-offset {
			return fmt.Errorf("invalid native archive length")
		}
		body := archive[offset : offset+size]
		// BSD archives store the extended member name before the object bytes.
		name := strings.TrimSpace(string(header[:16]))
		if strings.HasPrefix(name, "#1/") {
			count, err := strconv.Atoi(strings.TrimPrefix(name, "#1/"))
			if err != nil || count < 0 || count > len(body) {
				return fmt.Errorf("invalid archive member name")
			}
			body = body[count:]
		}
		known, correct := objectTarget(body, target)
		if known {
			objects++
			if !correct {
				return fmt.Errorf("native archive object target does not match")
			}
		}
		offset += size + (size & 1)
	}
	if objects == 0 {
		return fmt.Errorf("native archive has no target objects")
	}
	return nil
}

func objectTarget(body []byte, target string) (bool, bool) {
	if len(body) >= 20 && bytes.Equal(body[:4], []byte("\x7fELF")) {
		machine := binary.LittleEndian.Uint16(body[18:20])
		want := uint16(62)
		if target == "aarch64-unknown-linux-gnu" {
			want = 183
		}
		return true, strings.HasSuffix(target, "linux-gnu") && body[4] == 2 && body[5] == 1 && machine == want
	}
	if len(body) >= 8 && binary.LittleEndian.Uint32(body[:4]) == 0xfeedfacf {
		cpu := binary.LittleEndian.Uint32(body[4:8])
		want := uint32(0x01000007)
		if target == "aarch64-apple-darwin" {
			want = 0x0100000c
		}
		return true, strings.HasSuffix(target, "apple-darwin") && cpu == want
	}
	if len(body) >= 20 {
		machine := binary.LittleEndian.Uint16(body[:2])
		if machine == 0x8664 || machine == 0xaa64 {
			return true, target == "x86_64-pc-windows-gnu" && machine == 0x8664
		}
	}
	return false, false
}
