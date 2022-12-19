// Command wgctrl is a testing utility for interacting with WireGuard via package
// wgctrl.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func main() {
	flag.Parse()

	c, err := wgctrl.New()
	if err != nil {
		log.Fatalf("failed to open wgctrl: %v", err)
	}
	defer c.Close()

	var devices []*wgtypes.Device

	devices, err = c.Devices()
	if err != nil {
		log.Fatalf("failed to get devices: %v", err)
	}

	switch cmd := flag.Arg(0); cmd {
	case "show":
		iface := flag.Arg(1)
		if iface == "" || iface == "all" {
			showAll(devices)
		} else if iface == "interfaces" {
			showInterfaces(devices)
		} else {
			param := flag.Arg(2)
			if param == "endpoints" {
				showEndpoints(iface, devices)
			} else if param == "allowed-ips" {
				showAllowedIPs(iface, devices)
			} else {
				showDevice(iface, devices)
			}
		}
	case "showconf":
		iface := flag.Arg(1)
		if iface != "" {
			showConf(iface, devices)
		}
	default:
		showAll(devices)
	}
}

func showConf(name string, devices []*wgtypes.Device) {
	device := getDevice(name, devices)
	if device != nil {
		fmt.Printf("[Interface]\n")
		fmt.Printf("ListenPort = %d\n", device.ListenPort)
		fmt.Printf("PrivateKey = %s\n", device.PrivateKey.String())
		for _, peer := range device.Peers {
			fmt.Printf("\n[Peer]\n")
			fmt.Printf("PublicKey = %s\n", peer.PublicKey.String())
			fmt.Printf("AllowedIPS = %s\n", ipsString(peer.AllowedIPs, ", "))
			fmt.Printf("Endpoint = %s\n", peer.Endpoint.String())
			fmt.Printf("PersistentKeepalive = %0.f\n", peer.PersistentKeepaliveInterval.Seconds())
		}
	}
	fmt.Printf("\n")
}

func getDevice(name string, devices []*wgtypes.Device) *wgtypes.Device {
	for _, device := range devices {
		if device.Name == name {
			return device
		}
	}
	return nil
}

func showEndpoints(name string, devices []*wgtypes.Device) {
	device := getDevice(name, devices)
	if device != nil {
		for _, peer := range device.Peers {
			fmt.Printf("%s    %s", peer.PublicKey.String(), peer.Endpoint.String())
		}
	}
	fmt.Printf("\n")
}

func showAllowedIPs(name string, devices []*wgtypes.Device) {
	device := getDevice(name, devices)
	if device != nil {
		for _, peer := range device.Peers {
			fmt.Printf("%s    %s", peer.PublicKey.String(), ipsString(peer.AllowedIPs, " "))
		}
	}
	fmt.Printf("\n")
}

func showInterfaces(devices []*wgtypes.Device) {
	for _, device := range devices {
		fmt.Printf("%s ", device.Name)
	}
	fmt.Print("\n")
}

func showAll(devices []*wgtypes.Device) {
	for _, device := range devices {
		printDeviceInfo(device)
	}
}

func showDevice(name string, devices []*wgtypes.Device) {
	device := getDevice(name, devices)
	if device != nil {
		printDeviceInfo(device)
	}
}

func printDeviceInfo(device *wgtypes.Device) {
	printDevice(device)

	for _, p := range device.Peers {
		printPeer(p)
	}
}

func printDevice(d *wgtypes.Device) {
	const f = `interface: %s (%s)
  public key: %s
  private key: (hidden)
  listening port: %d

`

	fmt.Printf(
		f,
		d.Name,
		d.Type.String(),
		d.PublicKey.String(),
		d.ListenPort)
}

func printPeer(p wgtypes.Peer) {
	const f = `peer: %s
  endpoint: %s
  allowed ips: %s
  transfer: %d B received, %d B sent
  persistent keepalive: every %0.f seconds
`

	fmt.Printf(
		f,
		p.PublicKey.String(),
		// TODO(mdlayher): get right endpoint with getnameinfo.
		p.Endpoint.String(),
		ipsString(p.AllowedIPs, ", "),
		//		p.LastHandshakeTime.String(),
		p.ReceiveBytes,
		p.TransmitBytes,
		p.PersistentKeepaliveInterval.Seconds(),
	)
}

func ipsString(ipns []net.IPNet, sep string) string {
	ss := make([]string, 0, len(ipns))
	for _, ipn := range ipns {
		ss = append(ss, ipn.String())
	}

	return strings.Join(ss, sep)
}
