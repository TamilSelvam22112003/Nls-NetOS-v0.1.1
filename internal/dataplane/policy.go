package dataplane

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
)

type Action uint8
const (
	Protect Action = 1
	Bypass Action = 2
)
type Entry struct { Prefix netip.Prefix; Action Action }
type Policy struct { mu sync.RWMutex; entries []Entry; generation uint64 }
func NewPolicy() *Policy { return &Policy{} }
func (p *Policy) Generation() uint64 { p.mu.RLock();defer p.mu.RUnlock();return p.generation }
func (p *Policy) Entries() []Entry { p.mu.RLock();defer p.mu.RUnlock();return append([]Entry(nil),p.entries...) }
func (p *Policy) Replace(generation uint64,entries []Entry) error {
	if generation==0{return errors.New("policy generation must be nonzero")}
	candidate:=append([]Entry(nil),entries...)
	for i:=range candidate {
		e:=candidate[i]
		if !e.Prefix.IsValid()||e.Prefix!=e.Prefix.Masked(){return fmt.Errorf("prefix %q invalid or has host bits set",e.Prefix)}
		if e.Action!=Protect&&e.Action!=Bypass{return fmt.Errorf("prefix %s has invalid action",e.Prefix)}
		for j:=0;j<i;j++ {
			prior:=candidate[j]
			if prior.Prefix==e.Prefix{return fmt.Errorf("duplicate policy prefix %s",e.Prefix)}
			if prior.Action!=e.Action&&(prior.Prefix.Contains(e.Prefix.Addr())||e.Prefix.Contains(prior.Prefix.Addr())) {
				return fmt.Errorf("conflicting overlapping policy prefixes %s and %s",prior.Prefix,e.Prefix)
			}
		}
	}
	sort.Slice(candidate,func(i,j int)bool{if candidate[i].Prefix.Addr().BitLen()!=candidate[j].Prefix.Addr().BitLen(){return candidate[i].Prefix.Addr().BitLen()<candidate[j].Prefix.Addr().BitLen()};return candidate[i].Prefix.Bits()<candidate[j].Prefix.Bits()})
	p.mu.Lock();defer p.mu.Unlock()
	if generation<=p.generation{return errors.New("policy generation must increase")}
	p.entries=candidate;p.generation=generation
	return nil
}
func (p *Policy) Lookup(dst netip.Addr)(Action,bool) {
	if !dst.IsValid(){return 0,false}
	p.mu.RLock();defer p.mu.RUnlock()
	bestBits:=-1;var action Action
	for _,e:=range p.entries {
		if e.Prefix.Addr().BitLen()!=dst.BitLen()||!e.Prefix.Contains(dst){continue}
		if e.Prefix.Bits()>bestBits{bestBits=e.Prefix.Bits();action=e.Action}
	}
	return action,bestBits>=0
}
func Destination(packet []byte)(netip.Addr,error) {
	if err:=validateInnerPacket(packet);err!=nil{return netip.Addr{},err}
	switch packet[0]>>4 {
	case 4:var b [4]byte;copy(b[:],packet[16:20]);return netip.AddrFrom4(b),nil
	case 6:var b [16]byte;copy(b[:],packet[24:40]);return netip.AddrFrom16(b),nil
	default:return netip.Addr{},ErrBadInnerPacket
	}
}
type Disposition uint8
const (
	Drop Disposition = iota
	ProtectPacket
	BypassPacket
)
type Selector struct { Policy *Policy; Sessions map[netip.Prefix]*Session }
func (s *Selector) Protect(packet []byte)(Disposition,*Session,error) {
	if s==nil||s.Policy==nil{return Drop,nil,nil}
	dst,err:=Destination(packet);if err!=nil{return Drop,nil,err}
	action,ok:=s.Policy.Lookup(dst);if !ok{return Drop,nil,nil}
	if action==Bypass{return BypassPacket,nil,nil}
	var best netip.Prefix;var selected *Session
	for prefix,session:=range s.Sessions {
		if prefix.IsValid()&&prefix.Addr().BitLen()==dst.BitLen()&&prefix.Contains(dst)&&prefix.Bits()>best.Bits(){best=prefix;selected=session}
	}
	if selected==nil{return Drop,nil,nil}
	return ProtectPacket,selected,nil
}
