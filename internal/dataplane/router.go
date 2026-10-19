package dataplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

var ErrPolicyDrop = errors.New("NLS policy has no matching destination; packet dropped")
type RouteSession struct {
	Prefix netip.Prefix
	Peer netip.AddrPort
	Session *Session
}
type Router struct {
	Policy *Policy
	TUN io.ReadWriteCloser
	UDP net.PacketConn
	mu sync.RWMutex
	routes []RouteSession
	byID map[uint16]RouteSession
}
func NewRouter(policy *Policy,tun io.ReadWriteCloser,udp net.PacketConn,routes []RouteSession)(*Router,error) {
	if policy==nil||tun==nil||udp==nil{return nil,errors.New("policy, TUN and UDP transport are required")}
	r:=&Router{Policy:policy,TUN:tun,UDP:udp,byID:make(map[uint16]RouteSession)}
	if err:=r.ReplaceSessions(routes);err!=nil{return nil,err}
	return r,nil
}
func (r *Router) ReplaceSessions(routes []RouteSession)error {
	next:=append([]RouteSession(nil),routes...);byID:=make(map[uint16]RouteSession,len(next))
	for _,route:=range next {
		if !route.Prefix.IsValid()||route.Prefix!=route.Prefix.Masked()||route.Session==nil||!route.Peer.IsValid()||!route.Peer.Addr().Is6()||route.Peer.Addr().Is4In6()||route.Peer.Port()==0{return errors.New("invalid NLS session route")}
		if _,ok:=byID[route.Session.ID()];ok{return fmt.Errorf("duplicate NLS session ID %d",route.Session.ID())}
		byID[route.Session.ID()]=route
	}
	r.mu.Lock();r.routes=next;r.byID=byID;r.mu.Unlock();return nil
}
func (r *Router) routeFor(dst netip.Addr)(RouteSession,bool) {
	r.mu.RLock();defer r.mu.RUnlock()
	best:=-1;var selected RouteSession
	for _,route:=range r.routes{if route.Prefix.Addr().BitLen()==dst.BitLen()&&route.Prefix.Contains(dst)&&route.Prefix.Bits()>best{best=route.Prefix.Bits();selected=route}}
	return selected,best>=0
}
// ProtectPacket is the policy gate for a packet read from nls0. It never
// returns plaintext as a fallback. BYPASS packets must use the ordinary kernel
// route and must not be injected into the TUN device.
func (r *Router) ProtectPacket(packet []byte)(wire []byte,peer netip.AddrPort,err error) {
	dst,err:=Destination(packet);if err!=nil{return nil,netip.AddrPort{},err}
	action,ok:=r.Policy.Lookup(dst);if !ok{return nil,netip.AddrPort{},ErrPolicyDrop}
	if action==Bypass{return nil,netip.AddrPort{},ErrPolicyDrop}
	route,ok:=r.routeFor(dst);if !ok||route.Session==nil{return nil,netip.AddrPort{},ErrNoSession}
	wire,err=route.Session.Encrypt(packet);if err!=nil{return nil,netip.AddrPort{},err}
	return wire,route.Peer,nil
}
func (r *Router) handleInbound(raw []byte,source netip.AddrPort)error {
	if len(raw)<CommonHeaderSize+DataHeaderSize||raw[0]!=Version||(raw[1]!=TypeData&&raw[1]!=TypeRekeyInit&&raw[1]!=TypeRekeyAck){return ErrMalformed}
	id:=uint16(raw[CommonHeaderSize+2])<<8|uint16(raw[CommonHeaderSize+3])
	r.mu.RLock();route,ok:=r.byID[id];r.mu.RUnlock()
	if !ok{return ErrNoSession}
	if source!=route.Peer{return ErrNoSession}
	switch raw[1] {
	case TypeData:
		plain,err:=route.Session.Decrypt(raw);if err!=nil{return err}
		_,err=r.TUN.Write(plain);return err
	case TypeRekeyInit:
		ack,commit,err:=route.Session.AcceptRekey(raw);if err!=nil{return err}
		dst:=&net.UDPAddr{IP:net.IP(source.Addr().AsSlice()),Port:int(source.Port()),Zone:source.Addr().Zone()}
		if _,err=r.UDP.WriteTo(ack,dst);err!=nil{return err}
		return commit()
	case TypeRekeyAck:
		return route.Session.CompleteRekey(raw)
	}
	return ErrMalformed
}
func (r *Router) Run(ctx context.Context)error {
	errCh:=make(chan error,2)
	go func(){
		buf:=make([]byte,65535)
		for {
			select{case <-ctx.Done():errCh<-nil;return;default:}
			n,err:=r.TUN.Read(buf);if err!=nil{if ctx.Err()!=nil{errCh<-nil}else{errCh<-err};return}
			wire,peer,err:=r.ProtectPacket(append([]byte(nil),buf[:n]...));if err!=nil{continue}
			dst:=&net.UDPAddr{IP:net.IP(peer.Addr().AsSlice()),Port:int(peer.Port()),Zone:peer.Addr().Zone()}
			if _,err=r.UDP.WriteTo(wire,dst);err!=nil{if ctx.Err()!=nil{errCh<-nil}else{errCh<-err};return}
		}
	}()
	go func(){
		buf:=make([]byte,MaxUDPPayload+1)
		for {
			select{case <-ctx.Done():errCh<-nil;return;default:}
			if d,ok:=r.UDP.(interface{SetReadDeadline(time.Time)error});ok{_ = d.SetReadDeadline(time.Now().Add(time.Second))}
			n,from,err:=r.UDP.ReadFrom(buf);if err!=nil{
				if ctx.Err()!=nil{errCh<-nil;return}
				if ne,ok:=err.(net.Error);ok&&ne.Timeout(){continue}
				errCh<-err;return
			}
			if n>MaxUDPPayload{continue}
			source,err:=netAddrPort(from);if err!=nil{continue}
			_ = r.handleInbound(append([]byte(nil),buf[:n]...),source)
		}
	}()
	select{case <-ctx.Done():return nil;case err:=<-errCh:return err}
}
func (r *Router) Close()error {
	e1:=r.TUN.Close();e2:=r.UDP.Close()
	if e1!=nil{return e1};return e2
}
