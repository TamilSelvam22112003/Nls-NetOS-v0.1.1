//go:build linux

package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	tunSetIFF = 0x400454ca
	iffTun = 0x0001
	iffNoPI = 0x1000
)
type TUN struct { File *os.File; Name string }
func OpenTUN(name string,mtu int)(*TUN,error) {
	if name==""||len(name)>=16{return nil,errors.New("TUN name must be 1..15 bytes")}
	if mtu<1280||mtu>DefaultInnerMTU{return nil,fmt.Errorf("TUN MTU must be 1280..%d",DefaultInnerMTU)}
	f,err:=os.OpenFile("/dev/net/tun",os.O_RDWR,0);if err!=nil{return nil,fmt.Errorf("open /dev/net/tun (requires CAP_NET_ADMIN): %w",err)}
	ifr:=make([]byte,40);copy(ifr[:16],name);binary.LittleEndian.PutUint16(ifr[16:18],iffTun|iffNoPI)
	_,_,errno:=syscall.Syscall(syscall.SYS_IOCTL,f.Fd(),tunSetIFF,uintptr(unsafe.Pointer(&ifr[0])))
	if errno!=0{_ = f.Close();return nil,errno}
	actual:=strings.TrimRight(string(ifr[:16]),"\x00")
	if actual==""{_ = f.Close();return nil,errors.New("kernel returned empty TUN name")}
	t:=&TUN{File:f,Name:actual}
	if err:=runIP("link","set","dev",actual,"mtu",fmt.Sprint(mtu));err!=nil{_ = f.Close();return nil,err}
	if err:=runIP("link","set","dev",actual,"up");err!=nil{_ = f.Close();return nil,err}
	return t,nil
}
func (t *TUN) Read(p []byte)(int,error){return t.File.Read(p)}
func (t *TUN) Write(p []byte)(int,error){return t.File.Write(p)}
func (t *TUN) Close()error{return t.File.Close()}
func runIP(args ...string)error { out,err:=exec.Command("ip",args...).CombinedOutput();if err!=nil{return fmt.Errorf("ip %s: %w: %s",strings.Join(args," "),err,strings.TrimSpace(string(out)))};return nil }
func InstallPolicyRoutes(tunName string,entries []Entry,old []Entry)error {
	if tunName==""{return errors.New("TUN interface required")}
	// Protect prefixes get a blackhole first, so a failed TUN route update cannot
	// fall through to the ordinary default route and leak plaintext.
	for _,e:=range entries {
		if e.Action!=Protect{continue}
		if err:=runIP("route","replace",e.Prefix.String(),"blackhole");err!=nil{return err}
		if err:=runIP("route","replace",e.Prefix.String(),"dev",tunName);err!=nil{return err}
	}
	for _,e:=range old {
		if e.Action!=Protect{continue}
		found:=false;for _,n:=range entries{if n.Action==Protect&&n.Prefix==e.Prefix{found=true;break}}
		if !found{if err:=runIP("route","del",e.Prefix.String());err!=nil{return err}}
	}
	return nil
}
func ConfigureMSSClamp(tunName string,pathMTU int)error {
	mtu,err:=InnerMTU(pathMTU);if err!=nil{return err}
	mss4,mss6:=mtu-40,mtu-60
	for _,rule:=range [][]string{
		{"-t","mangle","-C","FORWARD","-o",tunName,"-p","tcp","--tcp-flags","SYN,RST","SYN","-j","TCPMSS","--set-mss",fmt.Sprint(mss4)},
		{"-t","mangle","-C","FORWARD","-o",tunName,"-p","ipv6-icmp","-j","RETURN"},
	} {
		_ = rule
	}
	for _,family:=range []struct{bin string;mss int}{{"iptables",mss4},{"ip6tables",mss6}} {
		check:=exec.Command(family.bin,"-t","mangle","-C","FORWARD","-o",tunName,"-p","tcp","--tcp-flags","SYN,RST","SYN","-j","TCPMSS","--set-mss",fmt.Sprint(family.mss))
		if err:=check.Run();err==nil{continue}
		cmd:=exec.Command(family.bin,"-t","mangle","-A","FORWARD","-o",tunName,"-p","tcp","--tcp-flags","SYN,RST","SYN","-j","TCPMSS","--set-mss",fmt.Sprint(family.mss))
		if out,err:=cmd.CombinedOutput();err!=nil{return fmt.Errorf("%s MSS clamp: %w: %s",family.bin,err,strings.TrimSpace(string(out)))}
	}
	return nil
}
