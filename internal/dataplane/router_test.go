package dataplane

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)
func TestProtectPacketFailsClosedAndSelectsPrefix(t *testing.T) {
	p:=NewPolicy();if err:=p.Replace(1,[]Entry{{netip.MustParsePrefix("10.0.0.0/8"),Protect}});err!=nil{t.Fatal(err)}
	i,r:=pair(t)
	route:=RouteSession{Prefix:netip.MustParsePrefix("10.0.0.0/8"),Peer:netip.MustParseAddrPort("[2001:db8::2]:4789"),Session:i}
	router:=&Router{Policy:p,routes:[]RouteSession{route},byID:map[uint16]RouteSession{i.ID():route}}
	packet:=ipv4Packet([]byte("confidential"))
	wire,peer,err:=router.ProtectPacket(packet);if err!=nil{t.Fatal(err)}
	if peer!=route.Peer{t.Fatal("wrong peer endpoint")}
	if bytes.Contains(wire,[]byte("confidential")){t.Fatal("plaintext leaked")}
	plain,err:=r.Decrypt(wire);if err!=nil||!bytes.Equal(plain,packet){t.Fatalf("peer decrypt failed: %v",err)}
	router.routes=nil
	if wire,_,err=router.ProtectPacket(packet);!errors.Is(err,ErrNoSession)||wire!=nil{t.Fatalf("missing session must drop: wire=%v err=%v",wire,err)}
}
func TestUnknownPolicyAndBypassNeverReturnPlaintext(t *testing.T) {
	p:=NewPolicy();if err:=p.Replace(1,[]Entry{{netip.MustParsePrefix("192.0.2.0/24"),Bypass}});err!=nil{t.Fatal(err)}
	router:=&Router{Policy:p}
	pkt:=ipv4Packet([]byte("must not be sent through NLS or leaked as fallback"));binary.BigEndian.PutUint32(pkt[16:20],0xc0000201)
	if wire,_,err:=router.ProtectPacket(pkt);!errors.Is(err,ErrPolicyDrop)||wire!=nil{t.Fatal("BYPASS arriving from TUN must be dropped, not plaintext-fallback")}
}
