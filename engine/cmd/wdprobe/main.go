// wdprobe checks that WinDivert can be loaded and opened on this machine.
// It must run elevated; it intercepts nothing (the filter never matches).
package main

import (
	"fmt"
	"os"

	"github.com/silverdragon101195/TunnelPick/engine/internal/windivert"
)

func main() {
	h, err := windivert.Open("false", windivert.LayerNetwork, 0, windivert.FlagSniff)
	if err != nil {
		fmt.Println("OPEN FAILED:", err)
		os.Exit(1)
	}
	defer h.Close()
	maj, _ := h.GetParam(windivert.ParamVersionMaj)
	min, _ := h.GetParam(windivert.ParamVersionMin)
	fmt.Printf("OK: WinDivert driver %d.%d loaded and handle opened\n", maj, min)
}
