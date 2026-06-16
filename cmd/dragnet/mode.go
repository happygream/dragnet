package main

import "github.com/happygream/dragnet/internal/model"

// detectMode decides which scan technique to advertise.
//
// v1 ships TCP-connect mode, which works everywhere with no admin rights and
// no driver. SYN mode is wired through the model but intentionally not the
// default: on Windows a raw SYN scan needs Npcap installed plus an elevated
// process, which cuts against the portable, no-install goal. When you add the
// gopacket/pcap path, flip this to return ModeSYN once both conditions hold:
//
//	1. the process is elevated (see isElevated below, per-OS build files), and
//	2. an Npcap/WinPcap capable device is openable.
//
// Until then everything runs portably in connect mode.
func detectMode() model.ScanMode {
	if isElevated() && hasRawCapture() {
		return model.ModeSYN
	}
	return model.ModeConnect
}

// hasRawCapture reports whether a raw packet-capture backend is available.
// Stubbed false until the gopacket path is added. Build with a `pcap` tag and
// implement this in a tagged file to light up SYN mode.
func hasRawCapture() bool { return false }
