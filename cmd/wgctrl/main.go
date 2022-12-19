// Command wgctrl is a testing utility for interacting with WireGuard via package
// wgctrl.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"gopkg.in/ini.v1"

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
	case "setconf":
		iface := flag.Arg(1)
		file := flag.Arg(2)
		if iface != "" && file != ""{
			setConf(iface, file, c)
		}
	default:
		showAll(devices)
	}
}

func setConf(name string, file string, client *wgctrl.Client) {
	ini_cfg, err := ini.LoadSources(ini.LoadOptions{
        AllowNonUniqueSections: true,
    }, file)
	if err != nil {
		log.Fatalf("error reading file %s : %s", file, err)
	}

	//	fmt.Printf("%v", ini_cfg)

	//	ini_cfg.SaveTo("./out.cfg")
	
	wg_cfg := wgtypes.Config{}

	section := ini_cfg.Section("Interface")

	if section.HasKey("PrivateKey") {
		skey := section.Key("PrivateKey").String()
		key, err := wgtypes.ParseKey(skey)
		if err != nil {
			log.Fatalf("error parsing private key %s : %s", skey, err)
		}
		wg_cfg.PrivateKey = &key
	}

	if section.HasKey("ListenPort") {
		listenPort, err := section.Key("ListenPort").Int()
		if err != nil {
			log.Fatalf("error parsing listen port %s : %s", section.Key("ListenPort").Value(), err)
		}
		wg_cfg.ListenPort = &listenPort
	}

	if section.HasKey("FirewallMark") {
		firewallMark, err := section.Key("FirewallMark").Int()
		if err != nil {
			log.Fatalf("error parsing firewall mark %s : %s", section.Key("FirewallMark").Value(), err)
		}
		wg_cfg.FirewallMark = &firewallMark
	}

	section = ini_cfg.Section("Peer")
	peer := wgtypes.PeerConfig{}

	if section.HasKey("PublicKey") {
		key, err := wgtypes.ParseKey(section.Key("PublicKey").String())
		if err != nil {
			log.Fatalf("error parsing public key %s : %s", section.Key("PublicKey").Value(), err)
		}
		peer.PublicKey = key
	}
	
	if section.HasKey("AllowedIPs") {
		ips := strings.Split(section.Key("AllowedIPs").String(), ", ")
		for _, ip := range ips {
			_, ipnet, err := net.ParseCIDR(ip)
			if err != nil {
				log.Fatalf("error parsing ip %s : %s", ip, err)
			}
			peer.AllowedIPs = append(peer.AllowedIPs, *ipnet)
		}
	}
	
	if section.HasKey("Endpoint") {
		saddr := section.Key("Endpoint").String()
		addr, err := net.ResolveUDPAddr("udp", saddr)
		if err != nil {
			log.Fatalf("error parsing endpoint %s : %s", saddr, err)
		}
		peer.Endpoint = addr
	}
	
	if section.HasKey("PersistentKeepalive") {
		seconds := fmt.Sprintf("%ss", section.Key("PersistentKeepalive").String())
		duration, err := time.ParseDuration(seconds)
		if err != nil {
			log.Fatalf("error parsing persistent keepalive %s : %s", seconds, err)
		}
		peer.PersistentKeepaliveInterval = &duration
	}

	wg_cfg.Peers = append(wg_cfg.Peers, peer)

	err = client.ConfigureDevice(name, wg_cfg)
	
	if err != nil {
		log.Fatalf("error setting configuration %v : %s", wg_cfg, err)
	}
}

func showConf(name string, devices []*wgtypes.Device) {
	device := getDevice(name, devices)
	if device != nil {
		fmt.Printf("[Interface]\n")
		if device.ListenPort != 0 {
			fmt.Printf("ListenPort = %d\n", device.ListenPort)
		}
		if device.FirewallMark != 0 {
			fmt.Printf("FwMark = 0x%x\n", device.FirewallMark)
		}
		fmt.Printf("PrivateKey = %s\n", device.PrivateKey.String())
		for _, peer := range device.Peers {
			fmt.Printf("\n[Peer]\n")
			fmt.Printf("PublicKey = %s\n", peer.PublicKey.String())
			if peer.PresharedKey.String() != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
				fmt.Printf("PresharedKey = %s\n", peer.PresharedKey.String())
			}
			fmt.Printf("AllowedIPS = %s\n", ipsString(peer.AllowedIPs, ", "))
			fmt.Printf("Endpoint = %s\n", peer.Endpoint.String())
			if peer.PersistentKeepaliveInterval != 0 {
				fmt.Printf("PersistentKeepalive = %0.f\n", peer.PersistentKeepaliveInterval.Seconds())
			}
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
