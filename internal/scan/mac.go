package scan

import (
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// ouiVendors maps an OUI prefix (first three MAC octets, uppercase, no
// separators) to a vendor label. This is a curated set covering common
// homelab, network, and consumer hardware rather than the full IEEE registry,
// which is too large to embed. Unknown prefixes simply return no vendor.
var ouiVendors = map[string]string{
	"FCECDA": "Ubiquiti", "0418D6": "Ubiquiti", "788A20": "Ubiquiti",
	"24A43C": "Ubiquiti", "B4FBE4": "Ubiquiti", "687251": "Ubiquiti",
	"002722": "Ubiquiti", "44D9E7": "Ubiquiti", "E063DA": "Ubiquiti",
	"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
	"2CCF67": "Raspberry Pi", "D83ADD": "Raspberry Pi", "28CDC1": "Raspberry Pi",
	"001132": "Synology",
	"F0795E": "Dell", "B083FE": "Dell", "18DBF2": "Dell", "D067E5": "Dell",
	"842B2B": "Dell", "001AA0": "Dell", "5CF9DD": "Dell", "F8BC12": "Dell",
	"001E67": "Intel", "3CFDFE": "Intel", "A0A8CD": "Intel", "94C691": "Intel",
	"001517": "Intel",
	"0050F2": "Microsoft", "00155D": "Microsoft Hyper-V",
	"000C29": "VMware", "005056": "VMware", "001C14": "VMware", "000569": "VMware",
	"080027": "VirtualBox", "0A0027": "VirtualBox",
	"525400": "QEMU/KVM",
	"F4F5E8": "Google", "3C5AB4": "Google",
	"AC63BE": "Amazon", "FCA183": "Amazon", "44650D": "Amazon",
	"D4F513": "Apple", "F0989D": "Apple", "A85C2C": "Apple", "BCD074": "Apple",
	"7CD1C3": "Apple", "ACBC32": "Apple", "F86214": "Apple",
	"E89F80": "Belkin", "C0C9E3": "Belkin", "001CDF": "Belkin",
	"00095B": "Netgear", "20E52A": "Netgear", "A040A0": "Netgear",
	"C8D719": "Cisco", "00000C": "Cisco",
	"E0CB4E": "Asustek", "AC220B": "Asustek", "2C56DC": "Asustek",
	"BCAEC5": "Asustek", "1C872C": "Asustek", "0011D8": "Asustek",
	"DC4427": "AVM (Fritz)", "3810D5": "AVM (Fritz)",
}

var macLineRe = regexp.MustCompile(`(?i)([0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}`)

// ResolveMAC reads the OS ARP table and returns the MAC and best-effort vendor
// for an IP on the local subnet. Returns empty strings if not found (e.g. the
// host is off-link, behind a router, or the table has not been populated).
func ResolveMAC(ip string) (mac, vendor string) {
	out, err := arpLookup(ip)
	if err != nil {
		return "", ""
	}
	m := macLineRe.FindString(out)
	if m == "" {
		return "", ""
	}
	mac = normalizeMAC(m)
	vendor = vendorFor(mac)
	return mac, vendor
}

// arpLookup shells out to the platform ARP utility for a single IP.
func arpLookup(ip string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		b, err := exec.Command("arp", "-a", ip).Output()
		return string(b), err
	default:
		b, err := exec.Command("arp", "-n", ip).Output()
		if err != nil {
			b, err = exec.Command("ip", "neigh", "show", ip).Output()
		}
		return string(b), err
	}
}

func normalizeMAC(m string) string {
	m = strings.ReplaceAll(m, "-", ":")
	m = strings.ToLower(m)
	parts := strings.Split(m, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

func vendorFor(mac string) string {
	hex := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	if len(hex) < 6 {
		return ""
	}
	return ouiVendors[hex[:6]]
}
