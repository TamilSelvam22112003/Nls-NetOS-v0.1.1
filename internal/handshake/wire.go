package handshake

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

const (
	WireVersion byte = 1
	TypeM1Init byte = 0x01
	TypeM1Cookie byte = 0x02
	TypeM2 byte = 0x03
	TypeM3 byte = 0x04
	TypeM4 byte = 0x05
	M1BodySize = 120
	M1FrameSize = 128
	M1CookieBodySize = 52
	M1CookieFrameSize = 60
	M2BodySize = 244
	M3BodySize = 178
	M4BodySize = 64
	HeaderSize = 8
)

var (
	ErrMalformed = errors.New("malformed handshake message")
	ErrBadCookie = errors.New("invalid or expired M1 cookie")
	ErrRateLimited = errors.New("M1 rate limited")
	ErrPendingLimit = errors.New("pending handshake limit reached")
	ErrHandshakeTimeout = errors.New("handshake timed out")
	ErrTranscript = errors.New("handshake transcript mismatch")
	ErrIdentity = errors.New("handshake identity binding failed")
	ErrSignature = errors.New("handshake signature invalid")
	ErrAEAD = errors.New("handshake AEAD verification failed")
)

type Message struct { Type byte; Body []byte; Raw []byte }

func frame(typ byte, body []byte) []byte {
	out:=make([]byte,HeaderSize+len(body))
	out[0],out[1]=WireVersion,typ
	binary.BigEndian.PutUint16(out[2:4],0)
	binary.BigEndian.PutUint16(out[4:6],uint16(len(body)))
	binary.BigEndian.PutUint16(out[6:8],0)
	copy(out[8:],body)
	return out
}

func parseFrame(raw []byte, typ byte, bodySize int)(Message,error){
	if len(raw)<HeaderSize||raw[0]!=WireVersion||raw[1]!=typ||binary.BigEndian.Uint16(raw[2:4])!=0||binary.BigEndian.Uint16(raw[6:8])!=0{return Message{},ErrMalformed}
	n:=int(binary.BigEndian.Uint16(raw[4:6]))
	if n!=bodySize||len(raw)!=HeaderSize+n{return Message{},ErrMalformed}
	return Message{Type:typ,Body:append([]byte(nil),raw[HeaderSize:]...),Raw:append([]byte(nil),raw...)},nil
}

type m1Fields struct {
	Nonce [32]byte
	InitiatorID [16]byte
	DestinationID [16]byte
	Ephemeral [32]byte
	CookiePresent bool
	Cookie [16]byte
}

func buildM1(f m1Fields) []byte {
	body:=make([]byte,M1BodySize)
	copy(body[0:32],f.Nonce[:]);copy(body[32:48],f.InitiatorID[:]);copy(body[48:64],f.DestinationID[:]);copy(body[64:96],f.Ephemeral[:])
	binary.BigEndian.PutUint16(body[96:98],1)
	if f.CookiePresent { body[100]=1;copy(body[101:117],f.Cookie[:]) }
	return frame(TypeM1Init,body)
}

func parseM1(raw []byte)(m1Fields,error){
	var f m1Fields
	m,err:=parseFrame(raw,TypeM1Init,M1BodySize);if err!=nil{return f,err}
	b:=m.Body
	if binary.BigEndian.Uint16(b[96:98])!=1||binary.BigEndian.Uint16(b[98:100])!=0||b[100]>1{return f,ErrMalformed}
	copy(f.Nonce[:],b[:32]);copy(f.InitiatorID[:],b[32:48]);copy(f.DestinationID[:],b[48:64]);copy(f.Ephemeral[:],b[64:96])
	f.CookiePresent=b[100]==1
	if !f.CookiePresent { for _,v:=range b[100:120]{if v!=0{return f,ErrMalformed}} } else {
		copy(f.Cookie[:],b[101:117]);for _,v:=range b[117:120]{if v!=0{return f,ErrMalformed}}
	}
	return f,nil
}

func frameHeader(typ byte, bodyLen int) []byte {
	h:=make([]byte,HeaderSize);h[0],h[1]=WireVersion,typ;binary.BigEndian.PutUint16(h[4:6],uint16(bodyLen));return h
}

func transcriptHash(parts ...[]byte) [32]byte { h:=sha256.New();for _,p:=range parts{_,_=h.Write(p)};var out [32]byte;copy(out[:],h.Sum(nil));return out }

func addrBytes(a netip.Addr)([]byte,error){
	if !a.IsValid()||!a.Is6()||a.Is4In6(){return nil,fmt.Errorf("NLS v1 handshake requires IPv6 addresses")}
	b:=a.As16();return b[:],nil
}

type CookieManager struct {
	mu sync.Mutex
	current uint32
	secrets map[uint32][32]byte
	now func()time.Time
}

func NewCookieManager(now func()time.Time)(*CookieManager,error){
	if now==nil{now=time.Now}
	c:=&CookieManager{now:now,secrets:make(map[uint32][32]byte)}
	if err:=c.rotateLocked(now());err!=nil{return nil,err}
	return c,nil
}

func cookieBucket(t time.Time)uint32{return uint32(t.Unix()/600)}

func (c *CookieManager) rotateLocked(now time.Time)error{
	bucket:=cookieBucket(now)
	if len(c.secrets)>0&&bucket==c.current{return nil}
	var secret [32]byte
	if _,err:=rand.Read(secret[:]);err!=nil{return err}
	oldBucket:=c.current
	oldSecrets:=c.secrets
	next:=make(map[uint32][32]byte,2)
	if len(oldSecrets)>0&&bucket==oldBucket+1 {
		if previous,ok:=oldSecrets[oldBucket];ok { next[oldBucket]=previous }
	}
	next[bucket]=secret
	c.secrets=next
	c.current=bucket
	return nil
}

func (c *CookieManager) Issue(src,dst netip.AddrPort,srcID,dstID [16]byte,nonce [32]byte,now time.Time)([16]byte,uint32,error){
	var cookie [16]byte
	c.mu.Lock();defer c.mu.Unlock()
	if err:=c.rotateLocked(now);err!=nil{return cookie,0,err}
	bucket:=cookieBucket(now);key:=c.secrets[bucket]
	mac,err:=cookieMAC(key,src,dst,srcID,dstID,nonce,bucket);if err!=nil{return cookie,0,err};copy(cookie[:],mac[:16]);return cookie,bucket,nil
}

func (c *CookieManager) Verify(src,dst netip.AddrPort,srcID,dstID [16]byte,nonce [32]byte,cookie [16]byte,now time.Time)bool{
	_,ok:=c.VerifyBucket(src,dst,srcID,dstID,nonce,cookie,now)
	return ok
}

// VerifyBucket recovers the cookie's bucket by testing the only two accepted
// buckets. M1_INIT(cookie) carries the 16-byte cookie but not the bucket field.
func (c *CookieManager) VerifyBucket(src,dst netip.AddrPort,srcID,dstID [16]byte,nonce [32]byte,cookie [16]byte,now time.Time)(uint32,bool){
	c.mu.Lock();defer c.mu.Unlock()
	if c.rotateLocked(now)!=nil{return 0,false}
	current:=cookieBucket(now)
	for _,bucket:=range []uint32{current,current-1}{
		key,ok:=c.secrets[bucket];if !ok{continue}
		mac,err:=cookieMAC(key,src,dst,srcID,dstID,nonce,bucket);if err!=nil{continue}
		if hmac.Equal(cookie[:],mac[:16]){return bucket,true}
	}
	return 0,false
}

func cookieMAC(key [32]byte,src,dst netip.AddrPort,srcID,dstID [16]byte,nonce [32]byte,bucket uint32)([32]byte,error){
	var out [32]byte
	sip,err:=addrBytes(src.Addr());if err!=nil{return out,err};dip,err:=addrBytes(dst.Addr());if err!=nil{return out,err}
	h:=hmac.New(sha256.New,key[:]);_,_=h.Write(sip)
	var port [2]byte;binary.BigEndian.PutUint16(port[:],uint16(src.Port()));_,_=h.Write(port[:])
	_,_=h.Write(dip);binary.BigEndian.PutUint16(port[:],uint16(dst.Port()));_,_=h.Write(port[:])
	_,_=h.Write(srcID[:]);_,_=h.Write(dstID[:]);_,_=h.Write(nonce[:])
	var b [4]byte;binary.BigEndian.PutUint32(b[:],bucket);_,_=h.Write(b[:]);copy(out[:],h.Sum(nil));return out,nil
}

type LimitConfig struct {
	GlobalRate float64
	GlobalBurst float64
	PerInterfaceRate float64
	PerInterfaceBurst float64
	PerPrefixRate float64
	PerPrefixBurst float64
	MaxTrackedPrefixes int
	PrefixIdleTTL time.Duration
	Interfaces []string
}

type tokenBucket struct { tokens float64; last time.Time }
func (b *tokenBucket) take(now time.Time,rate,burst float64)bool{
	if b.last.IsZero(){b.tokens=burst;b.last=now}
	if now.Before(b.last){return false}
	b.tokens+=now.Sub(b.last).Seconds()*rate;if b.tokens>burst{b.tokens=burst};b.last=now
	if b.tokens<1{return false};b.tokens--;return true
}

type M1Limiter struct {
	mu sync.Mutex
	cfg LimitConfig
	global tokenBucket
	interfaces map[string]*tokenBucket
	prefixes map[netip.Prefix]*tokenBucket
}

func NewM1Limiter(cfg LimitConfig)(*M1Limiter,error){
	if cfg.GlobalRate<=0||cfg.GlobalBurst<1||cfg.PerInterfaceRate<=0||cfg.PerInterfaceBurst<1||cfg.PerPrefixRate<=0||cfg.PerPrefixBurst<1||cfg.MaxTrackedPrefixes<1||cfg.PrefixIdleTTL<=0||len(cfg.Interfaces)==0{return nil,errors.New("all M1 rate/burst limits, prefix cap/idle TTL, and allowed ingress interfaces must be configured")}
	m:=&M1Limiter{cfg:cfg,interfaces:make(map[string]*tokenBucket),prefixes:make(map[netip.Prefix]*tokenBucket)}
	for _,name:=range cfg.Interfaces{if name==""{return nil,errors.New("empty ingress interface in M1 limiter")};if _,ok:=m.interfaces[name];ok{return nil,errors.New("duplicate ingress interface in M1 limiter")};m.interfaces[name]=&tokenBucket{tokens:cfg.PerInterfaceBurst}}
	return m,nil
}

func (m *M1Limiter) Allow(now time.Time,source netip.Addr,ingress string)bool{
	if !source.IsValid()||!source.Is6()||source.Is4In6(){return false}
	prefix:=netip.PrefixFrom(source,64).Masked()
	m.mu.Lock();defer m.mu.Unlock()
	iface,ok:=m.interfaces[ingress];if !ok{return false}
	for tracked,b:=range m.prefixes{if !now.Before(b.last)&&now.Sub(b.last)>m.cfg.PrefixIdleTTL{delete(m.prefixes,tracked)}}
	bucket,ok:=m.prefixes[prefix]
	if !ok { if len(m.prefixes)>=m.cfg.MaxTrackedPrefixes{return false};bucket=&tokenBucket{tokens:m.cfg.PerPrefixBurst};m.prefixes[prefix]=bucket }
	if !m.global.take(now,m.cfg.GlobalRate,m.cfg.GlobalBurst){return false}
	if !iface.take(now,m.cfg.PerInterfaceRate,m.cfg.PerInterfaceBurst){return false}
	if !bucket.take(now,m.cfg.PerPrefixRate,m.cfg.PerPrefixBurst){return false}
	return true
}
