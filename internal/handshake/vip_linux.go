package handshake

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// LinuxVIPProvider assigns a temporary IPv6 address, waits for DAD, restricts
// inbound traffic to the NLS handshake UDP port, and binds the M1 socket to it.
// DAD timings are explicit configuration because ADR-0005 defines no timeout.
type LinuxVIPProvider struct {
	IPCommand string
	IP6TablesCommand string
	DADTimeout time.Duration
	PollInterval time.Duration
}

func (p LinuxVIPProvider) Acquire(ctx context.Context,wanAddress netip.Addr,wanPrefix netip.Prefix,iface string,port uint16)(netip.Addr,net.PacketConn,func()error,error){
	if p.DADTimeout<=0||p.PollInterval<=0{return netip.Addr{},nil,nil,errors.New("DAD timeout and poll interval must be configured")}
	if iface==""||port==0{return netip.Addr{},nil,nil,errors.New("WAN interface and advertised UDP port are required")}
	if !wanAddress.Is6()||wanAddress.Is4In6()||!wanPrefix.IsValid()||!wanPrefix.Addr().Is6()||wanPrefix.Addr().Is4In6()||wanPrefix.Bits()>64||!wanPrefix.Contains(wanAddress){return netip.Addr{},nil,nil,errors.New("WAN address must be IPv6 inside a routed IPv6 prefix of /64 or shorter")}
	ipCmd:=p.IPCommand;if ipCmd==""{ipCmd="ip"}
	fwCmd:=p.IP6TablesCommand;if fwCmd==""{fwCmd="ip6tables"}
	vip,err:=generateVIP(wanAddress,wanPrefix);if err!=nil{return netip.Addr{},nil,nil,err}
	if err=runCommand(ctx,ipCmd,"-6","addr","add",vip.String()+"/128","dev",iface);err!=nil{return netip.Addr{},nil,nil,fmt.Errorf("assign temporary vIP: %w",err)}
	addressAdded:=true
	allowAdded,dropAdded:=false,false
	var conn *net.UDPConn
	var once sync.Once
	var releaseErr error
	release:=func()error{
		once.Do(func(){
			if conn!=nil{if e:=conn.Close();e!=nil&&releaseErr==nil{releaseErr=e}}
			if dropAdded{if e:=runCommand(context.Background(),fwCmd,"-D","INPUT","-d",vip.String(),"-j","DROP");e!=nil&&releaseErr==nil{releaseErr=e}}
			if allowAdded{if e:=runCommand(context.Background(),fwCmd,"-D","INPUT","-d",vip.String(),"-p","udp","--dport",fmt.Sprint(port),"-j","ACCEPT");e!=nil&&releaseErr==nil{releaseErr=e}}
			if addressAdded{if e:=runCommand(context.Background(),ipCmd,"-6","addr","del",vip.String()+"/128","dev",iface);e!=nil&&releaseErr==nil{releaseErr=e}}
		})
		return releaseErr
	}
	fail:=func(e error)(netip.Addr,net.PacketConn,func()error,error){_ = release();return netip.Addr{},nil,nil,e}
	deadline:=time.Now().Add(p.DADTimeout)
	for{
		if err=ctx.Err();err!=nil{return fail(err)}
		out,e:=exec.CommandContext(ctx,ipCmd,"-6","addr","show","dev",iface,"to",vip.String()).CombinedOutput()
		if e!=nil{return fail(fmt.Errorf("check vIP DAD state: %w: %s",e,strings.TrimSpace(string(out))))}
		state:=string(out)
		if strings.Contains(state,"dadfailed"){return fail(errors.New("temporary vIP duplicate-address detection failed"))}
		if strings.Contains(state,"inet6")&&!strings.Contains(state,"tentative"){break}
		if time.Now().After(deadline){return fail(errors.New("temporary vIP duplicate-address detection timed out"))}
		select{case <-ctx.Done():return fail(ctx.Err());case <-time.After(p.PollInterval):}
	}
	if err=runCommand(ctx,fwCmd,"-I","INPUT","1","-d",vip.String(),"-p","udp","--dport",fmt.Sprint(port),"-j","ACCEPT");err!=nil{return fail(fmt.Errorf("allow handshake UDP to temporary vIP: %w",err))}
	allowAdded=true
	if err=runCommand(ctx,fwCmd,"-I","INPUT","2","-d",vip.String(),"-j","DROP");err!=nil{return fail(fmt.Errorf("restrict inbound temporary vIP: %w",err))}
	dropAdded=true
	conn,err=net.ListenUDP("udp6",&net.UDPAddr{IP:net.IP(vip.AsSlice()),Port:int(port)})
	if err!=nil{return fail(fmt.Errorf("bind M1 socket to temporary vIP: %w",err))}
	return vip,conn,release,nil
}

func generateVIP(wanAddress netip.Addr,prefix netip.Prefix)(netip.Addr,error){
	if !wanAddress.Is6()||wanAddress.Is4In6()||!prefix.IsValid()||prefix.Bits()>64||!prefix.Contains(wanAddress){return netip.Addr{},errors.New("invalid IPv6 WAN prefix/address")}
	b:=wanAddress.As16();var iid [8]byte
	if _,err:=rand.Read(iid[:]);err!=nil{return netip.Addr{},err}
	copy(b[8:],iid[:])
	vip:=netip.AddrFrom16(b)
	if !prefix.Contains(vip)||vip==wanAddress{return netip.Addr{},errors.New("generated vIP is outside routed prefix")}
	return vip,nil
}

func runCommand(ctx context.Context,name string,args ...string)error{
	out,err:=exec.CommandContext(ctx,name,args...).CombinedOutput()
	if err!=nil{return fmt.Errorf("%s %v: %w: %s",name,args,err,strings.TrimSpace(string(out)))}
	return nil
}
