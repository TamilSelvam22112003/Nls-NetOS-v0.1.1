package control

import (
	"encoding/binary"
	"testing"
)

func TestParsePolicyValid(t *testing.T) {
	v:=make([]byte,12)
	binary.BigEndian.PutUint64(v[:8],7);binary.BigEndian.PutUint32(v[8:12],2)
	v=append(v,1,4,8,0,10,0,0,0)
	v=append(v,2,6,32,0,0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0)
	p,err:=parsePolicy(v);if err!=nil{t.Fatal(err)}
	if p.Generation!=7||len(p.Entries)!=2{t.Fatalf("parsed policy=%#v",p)}
}

func TestParsePolicyRejectsTruncationAndHostBits(t *testing.T) {
	truncated:=make([]byte,12);binary.BigEndian.PutUint32(truncated[8:12],1)
	if _,err:=parsePolicy(truncated);err==nil{t.Fatal("truncated entry accepted")}
	hostBits:=make([]byte,12);binary.BigEndian.PutUint32(hostBits[8:12],1)
	hostBits=append(hostBits,1,4,8,0,10,1,0,0)
	if _,err:=parsePolicy(hostBits);err==nil{t.Fatal("host bits accepted")}
}

func TestParsePolicyRejectsConflictingOverlap(t *testing.T) {
	v:=make([]byte,12);binary.BigEndian.PutUint32(v[8:12],2)
	v=append(v,1,4,8,0,10,0,0,0)
	v=append(v,2,4,16,0,10,1,0,0)
	if _,err:=parsePolicy(v);err==nil{t.Fatal("overlapping conflicting actions accepted")}
}

func TestParseRevocations(t *testing.T) {
	v:=make([]byte,12);binary.BigEndian.PutUint64(v[:8],1);binary.BigEndian.PutUint32(v[8:12],1)
	entry:=make([]byte,32);entry[15]=1;entry[16]=2;binary.BigEndian.PutUint64(entry[24:],123)
	v=append(v,entry...)
	r,err:=parseRevocations(v);if err!=nil{t.Fatal(err)}
	if r.Generation!=1||len(r.Entries)!=1||r.Entries[0].Status!=2{t.Fatalf("bad revocation parse %#v",r)}
	entry[20]=1
	bad:=append(append([]byte(nil),v[:12]...),entry...)
	if _,err=parseRevocations(bad);err==nil{t.Fatal("nonzero reserved byte accepted")}
}

func TestPolicyAckLayout(t *testing.T) {
	b:=policyAck(0x0102030405060708,1,0x000b)
	if len(b)!=12||binary.BigEndian.Uint64(b[:8])!=0x0102030405060708||binary.BigEndian.Uint16(b[8:10])!=1||binary.BigEndian.Uint16(b[10:])!=0x000b{t.Fatalf("bad ack layout %x",b)}
}
