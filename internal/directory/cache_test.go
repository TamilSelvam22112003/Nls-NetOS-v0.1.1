package directory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func signedTestRDR(t *testing.T, priv ed25519.PrivateKey, id [16]byte, now time.Time, status byte) []byte {
	t.Helper()
	body:=make([]byte,RDRBodySize);body[0],body[1]=1,1;copy(body[4:20],id[:])
	_,routerPriv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	copy(body[20:52],routerPriv.Public().(ed25519.PublicKey))
	body[52],body[53]=1,6;body[69]=1;binary.BigEndian.PutUint16(body[70:72],4789)
	binary.BigEndian.PutUint64(body[72:80],9)
	binary.BigEndian.PutUint64(body[80:88],uint64(now.Add(-time.Minute).UnixMilli()))
	binary.BigEndian.PutUint64(body[88:96],uint64(now.Add(time.Hour).UnixMilli()))
	body[96]=status;binary.BigEndian.PutUint64(body[104:112],1)
	msg:=append([]byte("NLS-v1-RDR\x00"),body...)
	return append(body,ed25519.Sign(priv,msg)...)
}

func TestVerifyRDRValidAndRejectsTampering(t *testing.T) {
	pub,priv,_:=ed25519.GenerateKey(rand.Reader);now:=time.Now().UTC();var id [16]byte;id[15]=7
	raw:=signedTestRDR(t,priv,id,now,1);r,err:=VerifyRDR(raw,pub,now);if err!=nil{t.Fatal(err)}
	if r.RouterID!=id||r.Endpoint.Port()!=4789||r.Generation!=1{t.Fatalf("unexpected RDR %#v",r)}
	raw[130]^=1;if _,err=VerifyRDR(raw,pub,now);!errors.Is(err,ErrInvalidRDR){t.Fatalf("tampered RDR accepted: %v",err)}
}

func TestVerifyRDRRejectsRevokedAndExpired(t *testing.T) {
	pub,priv,_:=ed25519.GenerateKey(rand.Reader);now:=time.Now().UTC();var id [16]byte
	if _,err:=VerifyRDR(signedTestRDR(t,priv,id,now,2),pub,now);err==nil{t.Fatal("revoked RDR accepted")}
	if _,err:=VerifyRDR(signedTestRDR(t,priv,id,now.Add(-2*time.Hour),1),pub,now);err==nil{t.Fatal("expired RDR accepted")}
}

func TestHandshakeLookupAlwaysOnlineAndNeverFallsBackToCache(t *testing.T) {
	caPub,caPriv,_:=ed25519.GenerateKey(rand.Reader);now:=time.Now().UTC();var id [16]byte;id[15]=3
	calls:=0;offline:=false
	lookup:=func(_ context.Context, got [16]byte)(uint16,[]byte,error){calls++;if got!=id{t.Fatal("wrong router ID")};if offline{return LookupUnavailable,nil,nil};return LookupFound,signedTestRDR(t,caPriv,id,now,1),nil}
	c,err:=NewCache(caPub,DefaultCacheTTL,lookup);if err!=nil{t.Fatal(err)}
	if _,err=c.LookupForHandshake(context.Background(),id);err!=nil{t.Fatal(err)}
	if _,ok:=c.GetCachedForDiagnostics(id);!ok{t.Fatal("fresh record not cached")}
	offline=true
	if _,err=c.LookupForHandshake(context.Background(),id);!errors.Is(err,ErrCAUnavailable){t.Fatalf("offline handshake lookup = %v",err)}
	if calls!=2{t.Fatalf("lookup calls=%d; each handshake must query CA",calls)}
	if _,ok:=c.GetCachedForDiagnostics(id);!ok{t.Fatal("offline lookup should not delete TTL-valid diagnostic cache")}
}

func TestHandshakeLookupRejectsUnknownAndRevoked(t *testing.T) {
	pub,_,_:=ed25519.GenerateKey(rand.Reader);var id [16]byte
	for _,tc:=range []struct{name string;status uint16;want error}{{"unknown",LookupUnknown,ErrUnknownRouter},{"revoked",LookupRevoked,ErrRevoked}}{
		t.Run(tc.name,func(t *testing.T){c,_:=NewCache(pub,time.Minute,func(context.Context,[16]byte)(uint16,[]byte,error){return tc.status,nil,nil});_,err:=c.LookupForHandshake(context.Background(),id);if !errors.Is(err,tc.want){t.Fatalf("got %v, want %v",err,tc.want)}})
	}
}

func TestCacheTTLAndClockRollback(t *testing.T) {
	pub,priv,_:=ed25519.GenerateKey(rand.Reader);now:=time.Now().UTC();var id [16]byte
	c,err:=NewCache(pub,time.Minute,func(context.Context,[16]byte)(uint16,[]byte,error){return LookupFound,signedTestRDR(t,priv,id,now,1),nil});if err!=nil{t.Fatal(err)}
	if _,err=c.LookupForHandshake(context.Background(),id);err!=nil{t.Fatal(err)}
	c.now=func()time.Time{return now.Add(61*time.Second)}
	if _,ok:=c.GetCachedForDiagnostics(id);ok{t.Fatal("expired cache entry returned")}
	c.now=func()time.Time{return now.Add(-time.Second)}
	if _,ok:=c.GetCachedForDiagnostics(id);ok{t.Fatal("clock rollback must not make cache fresh")}
}
