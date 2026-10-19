package dataplane

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)
func pair(t *testing.T)(*Session,*Session) {
	t.Helper();var nonceID [16]byte;nonceID[0]=7
	var i2r,r2i [32]byte;var si,sr [4]byte;i2r[0]=1;r2i[0]=2;si[0]=3;sr[0]=4
	now:=time.Unix(1800000000,0)
	i,err:=NewSession(Config{SessionID:7,NonceID:nonceID,SendKey:i2r,ReceiveKey:r2i,SendSalt:si,ReceiveSalt:sr,Now:func()time.Time{return now}});if err!=nil{t.Fatal(err)}
	r,err:=NewSession(Config{SessionID:7,NonceID:nonceID,SendKey:r2i,ReceiveKey:i2r,SendSalt:sr,ReceiveSalt:si,Now:func()time.Time{return now}});if err!=nil{t.Fatal(err)}
	return i,r
}
func ipv4Packet(payload []byte)[]byte { p:=make([]byte,20+len(payload));p[0]=0x45;binary.BigEndian.PutUint16(p[2:4],uint16(len(p)));p[8]=64;p[9]=17;copy(p[12:16],[]byte{10,0,0,1});copy(p[16:20],[]byte{10,0,0,2});copy(p[20:],payload);return p }
func TestDataRoundTripAndNoPlaintextLeak(t *testing.T) {
	i,r:=pair(t);plain:=ipv4Packet([]byte("sensitive payload"));wire,err:=i.Encrypt(plain);if err!=nil{t.Fatal(err)}
	if bytes.Contains(wire,[]byte("sensitive payload")){t.Fatal("plaintext leaked into wire datagram")}
	got,err:=r.Decrypt(wire);if err!=nil{t.Fatal(err)};if !bytes.Equal(got,plain){t.Fatal("round trip mismatch")}
}
func TestReplayRejected(t *testing.T) {
	i,r:=pair(t);wire,err:=i.Encrypt(ipv4Packet([]byte("one")));if err!=nil{t.Fatal(err)}
	if _,err=r.Decrypt(wire);err!=nil{t.Fatal(err)}
	if _,err=r.Decrypt(wire);!errors.Is(err,ErrReplay){t.Fatalf("expected replay rejection, got %v",err)}
}
func TestBadTagRejectedWithoutPlaintext(t *testing.T) {
	i,r:=pair(t);wire,err:=i.Encrypt(ipv4Packet([]byte("secret")));if err!=nil{t.Fatal(err)}
	wire[len(wire)-1]^=0x80
	got,err:=r.Decrypt(wire);if !errors.Is(err,ErrBadTag){t.Fatalf("expected bad tag, got %v",err)}
	if got!=nil{t.Fatal("plaintext returned for invalid tag")}
	// An unauthenticated high sequence must not move the replay window.
	wire2,err:=i.Encrypt(ipv4Packet([]byte("next")));if err!=nil{t.Fatal(err)}
	if _,err=r.Decrypt(wire2);err!=nil{t.Fatalf("valid packet rejected after forged tag: %v",err)}
}
func TestOldSequenceOutsideWindowRejected(t *testing.T) {
	i,r:=pair(t);packets:=make([][]byte,1025)
	for n:=range packets { var err error;packets[n],err=i.Encrypt(ipv4Packet([]byte{byte(n)}));if err!=nil{t.Fatal(err)} }
	if _,err:=r.Decrypt(packets[1024]);err!=nil{t.Fatal(err)}
	if _,err:=r.Decrypt(packets[0]);!errors.Is(err,ErrReplay){t.Fatalf("old packet should be rejected: %v",err)}
}
func TestOversizePacketRejected(t *testing.T) {
	i,_:=pair(t);p:=ipv4Packet(bytes.Repeat([]byte{1},DefaultInnerMTU))
	if _,err:=i.Encrypt(p);!errors.Is(err,ErrOversize){t.Fatalf("expected oversize rejection, got %v",err)}
}
func TestRekeyInstallSwitchesKeysAndResetsCounters(t *testing.T) {
	i,r:=pair(t);var keys Keys;keys.I2R[0]=9;keys.R2I[0]=8;keys.SaltI2R[0]=7;keys.SaltR2I[0]=6
	var transcript [32]byte;transcript[0]=1
	if err:=i.InstallRekey(1,keys,transcript);err!=nil{t.Fatal(err)}
	if err:=r.InstallRekey(1,keys,transcript);err!=nil{t.Fatal(err)}
	wire,err:=i.Encrypt(ipv4Packet([]byte("after rekey")));if err!=nil{t.Fatal(err)}
	if binary.BigEndian.Uint64(wire[CommonHeaderSize+20:CommonHeaderSize+28])!=1{t.Fatal("sequence must restart at 1 after key switch")}
	got,err:=r.Decrypt(wire);if err!=nil{t.Fatal(err)};if string(got[20:])!="after rekey"{t.Fatal("post-rekey plaintext mismatch")}
}
func TestRekeyThresholdAndHardStop(t *testing.T) {
	var nonce [16]byte
	s,err:=NewSession(Config{SessionID:1,NonceID:nonce,InnerMTU:1396,RekeyAfterPackets:2,HardStopPackets:5,RekeyAfter:time.Hour});if err!=nil{t.Fatal(err)}
	for n:=0;n<2;n++ {if _,err=s.Encrypt(ipv4Packet(nil));err!=nil{t.Fatal(err)}}
	if _,err=s.Encrypt(ipv4Packet(nil));!errors.Is(err,ErrRekeyRequired){t.Fatalf("expected rekey required, got %v",err)}
	// Authenticated rekey makes the new epoch usable again.
	var keys Keys;keys.I2R[0]=1;keys.R2I[0]=2
	if err=s.InstallRekey(1,keys,[32]byte{});err!=nil{t.Fatal(err)}
	if _,err=s.Encrypt(ipv4Packet(nil));err!=nil{t.Fatal(err)}
}
func TestMSSAndMTUArithmetic(t *testing.T) {
	mtu,err:=InnerMTU(1500);if err!=nil||mtu!=1396{t.Fatalf("MTU=%d err=%v",mtu,err)}
	v4,v6,err:=MSSClamp(1500);if err!=nil||v4!=1356||v6!=1336{t.Fatalf("MSS=%d/%d err=%v",v4,v6,err)}
	if _,err=InnerMTU(1300);err==nil{t.Fatal("path MTU too small for IPv6 must fail")}
	_ = netip.Addr{}
}
