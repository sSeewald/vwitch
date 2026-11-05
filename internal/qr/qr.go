// Package qr renders QR codes for client configs as terminal text or SVG.
package qr

import (
	"fmt"
	"strings"

	qrcode "github.com/yeqown/go-qrcode/v2"
)

const quiet = 2 // modules of white border

type grabber struct{ bits [][]bool }

func (g *grabber) Write(m qrcode.Matrix) error { g.bits = m.Bitmap(); return nil }
func (g *grabber) Close() error                { return nil }

// Matrix returns the module bitmap [row][col] with a quiet zone; true is dark.
func Matrix(text string) ([][]bool, error) {
	code, err := qrcode.NewWith(text, qrcode.WithErrorCorrectionLevel(qrcode.ErrorCorrectionLow))
	if err != nil {
		return nil, err
	}
	g := &grabber{}
	if err := code.Save(g); err != nil {
		return nil, err
	}
	n := len(g.bits) + 2*quiet
	out := make([][]bool, n)
	for y := range out {
		out[y] = make([]bool, n)
		if y >= quiet && y < n-quiet {
			copy(out[y][quiet:], g.bits[y-quiet])
		}
	}
	return out, nil
}

// Terminal renders the code with ANSI colors, two rows per text line, so it
// scans regardless of the terminal's color scheme.
func Terminal(text string) (string, error) {
	m, err := Matrix(text)
	if err != nil {
		return "", err
	}
	color := func(dark bool, base int) int {
		if dark {
			return base // black
		}
		return base + 7 // white
	}
	var b strings.Builder
	for y := 0; y < len(m); y += 2 {
		for x := range m[y] {
			bottom := false
			if y+1 < len(m) {
				bottom = m[y+1][x]
			}
			fmt.Fprintf(&b, "\x1b[%d;%dm▀", color(m[y][x], 30), color(bottom, 40))
		}
		b.WriteString("\x1b[0m\n")
	}
	return b.String(), nil
}

// SVG renders the code as a scalable SVG image.
func SVG(text string) (string, error) {
	m, err := Matrix(text)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`, len(m), len(m))
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, len(m), len(m))
	for y, row := range m {
		for x, dark := range row {
			if dark {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}
