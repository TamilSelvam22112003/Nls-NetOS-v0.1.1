package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"
)
func TestPolicyLPMAndFailClosed(t *testing.T) {
	p:=NewPolicy()
	if err:=p.Replace(1,[]Entry{{netip.MustParsePrefix("10.0.0.0/8"),Protect},{netip.MustParsePrefix("192.0.2.0/24"),Bypass}});err!=nil{t.Fatal(err)}
	a,ok:=p.Lookup(netip.MustParseAddr("10.2.3.4"));if !ok||a!=Protect{t.Fatal("protect prefix not selected")}
	a,ok=p.Lookup(netip.MustParseAddr("192.0.2.4"));if !ok||a!=Bypass{t.Fatal("explicit bypass not selected")}
	if _,ok=p.Lookup(netip.MustParseAddr("203.0.113.4"));ok{t.Fatal("unmatched destination must not become permissive")}
	s:=Selector{Policy:p,Sessions:map[netip.Prefix]*Session{}}
	packet:=make([]byte,20);packet[0]=0x45;binary.BigEndian.PutUint16(packet[2:4],20);copy(packet[16:20],[]byte{10,1,2,3})
	d,session,err:=s.Protect(packet);if err!=nil||d!=Drop||session!=nil{t.Fatal("PROTECT without session must drop")}
}
func TestPolicyRejectsConflictingOverlapAndHostBits(t *testing.T) {
	p:=NewPolicy()
	if err:=p.Replace(1,[]Entry{{netip.MustParsePrefix("10.0.0.0/8"),Protect},{netip.MustParsePrefix("10.1.0.0/16"),Bypass}});err==nil{t.Fatal("conflicting overlap must reject policy")}
	if err:=p.Replace(1,[]Entry{{netip.MustParsePrefix("10.1.2.3/24"),Protect}});err==nil{t.Fatal("host bits must reject policy")}
}
