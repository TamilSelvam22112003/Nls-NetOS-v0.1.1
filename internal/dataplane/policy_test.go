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

func TestPolicyRejectsProtectOverlapWithUnderlayControlOrRouting(t *testing.T) {
	reserved := []netip.Prefix{
		netip.MustParsePrefix("2001:db8:1::/64"), // router underlay
		netip.MustParsePrefix("2001:db8:2::10/128"), // CA/control endpoint
		netip.MustParsePrefix("224.0.0.0/24"), // IPv4 routing/control multicast
	}
	p := NewPolicy(reserved...)
	for _, tc := range []struct {
		name string
		prefix netip.Prefix
	}{
		{"underlay containing protected prefix", netip.MustParsePrefix("2001:db8:1::/80")},
		{"protected prefix containing CA address", netip.MustParsePrefix("2001:db8:2::/64")},
		{"routing multicast", netip.MustParsePrefix("224.0.0.0/24")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := p.Replace(1, []Entry{{Prefix: tc.prefix, Action: Protect}}); err == nil {
				t.Fatalf("PROTECT prefix %s overlaps a reserved address range but was accepted", tc.prefix)
			}
		})
	}
}

func TestPolicyAllowsNonOverlappingProtectedPrefixWithGuard(t *testing.T) {
	p := NewPolicy(netip.MustParsePrefix("2001:db8:1::/64"), netip.MustParsePrefix("2001:db8:2::10/128"))
	if err := p.Replace(1, []Entry{{Prefix: netip.MustParsePrefix("2001:db8:30::/48"), Action: Protect}}); err != nil {
		t.Fatalf("unrelated protected prefix rejected: %v", err)
	}
}
