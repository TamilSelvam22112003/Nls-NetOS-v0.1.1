// Package directory implements the router's signed Router Directory Record cache.
// Cached records are never sufficient authorization for a new handshake: every
// handshake must call LookupForHandshake, which performs an online CA lookup.
package directory

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

const (
	RDRBodySize = 258
	RDRSize = RDRBodySize + ed25519.SignatureSize
	DefaultCacheTTL = 300 * time.Second
	LookupFound uint16 = 0
	LookupUnknown uint16 = 1
	LookupRevoked uint16 = 2
	LookupUnavailable uint16 = 3
)

var (
	ErrCAUnavailable = errors.New("Router-CA lookup unavailable")
	ErrUnknownRouter = errors.New("Router-CA does not know router")
	ErrRevoked = errors.New("router is revoked or disabled")
	ErrInvalidRDR = errors.New("invalid Router Directory Record")
)

type Record struct {
	RouterID [16]byte
	PublicKey ed25519.PublicKey
	Endpoint netip.AddrPort
	CertificateSerial uint64
	NotBefore time.Time
	NotAfter time.Time
	Generation uint64
	Raw []byte
}

type LookupFunc func(context.Context, [16]byte) (status uint16, rdr []byte, err error)

type cachedRecord struct { record Record; fetchedAt time.Time }

type Cache struct {
	caPublicKey ed25519.PublicKey
	ttl time.Duration
	lookup LookupFunc
	now func() time.Time
	mu sync.RWMutex
	records map[[16]byte]cachedRecord
}

func NewCache(caPublicKey ed25519.PublicKey, ttl time.Duration, lookup LookupFunc) (*Cache, error) {
	if len(caPublicKey) != ed25519.PublicKeySize { return nil, errors.New("Router-CA Ed25519 public key must be 32 bytes") }
	if lookup == nil { return nil, errors.New("online Router-CA lookup is required") }
	if ttl <= 0 { ttl = DefaultCacheTTL }
	return &Cache{caPublicKey:append(ed25519.PublicKey(nil),caPublicKey...),ttl:ttl,lookup:lookup,now:time.Now,records:make(map[[16]byte]cachedRecord)},nil
}

// LookupForHandshake always performs an online lookup. On transport failure or
// status UNAVAILABLE it returns an error even if a cached RDR exists.
func (c *Cache) LookupForHandshake(ctx context.Context, routerID [16]byte) (Record, error) {
	status, raw, err := c.lookup(ctx, routerID)
	if err != nil { return Record{}, fmt.Errorf("%w: %v",ErrCAUnavailable,err) }
	switch status {
	case LookupUnknown: return Record{},ErrUnknownRouter
	case LookupRevoked: return Record{},ErrRevoked
	case LookupUnavailable: return Record{},ErrCAUnavailable
	case LookupFound:
	default: return Record{},fmt.Errorf("%w: unknown lookup status %d",ErrInvalidRDR,status)
	}
	record,err:=VerifyRDR(raw,c.caPublicKey,c.now())
	if err!=nil{return Record{},err}
	if subtle.ConstantTimeCompare(record.RouterID[:],routerID[:])!=1{return Record{},fmt.Errorf("%w: router ID does not match lookup",ErrInvalidRDR)}
	c.mu.Lock()
	c.records[routerID]=cachedRecord{record:cloneRecord(record),fetchedAt:c.now()}
	c.mu.Unlock()
	return cloneRecord(record),nil
}

// GetCachedForDiagnostics returns a TTL-valid record for display/diagnostics only.
// Handshake code must use LookupForHandshake instead.
func (c *Cache) GetCachedForDiagnostics(routerID [16]byte) (Record, bool) {
	c.mu.RLock(); entry,ok:=c.records[routerID]; c.mu.RUnlock()
	if !ok{return Record{},false}
	now:=c.now()
	if now.Before(entry.fetchedAt)||now.Sub(entry.fetchedAt)>c.ttl||!now.Before(entry.record.NotAfter)||now.Before(entry.record.NotBefore){return Record{},false}
	return cloneRecord(entry.record),true
}

func (c *Cache) TTL() time.Duration { return c.ttl }

// VerifyRDR validates the frozen v1 RDR layout, signature, status, endpoint,
// validity window, and reserved bytes. The CA public key comes from the pinned root.
func VerifyRDR(raw []byte, caPublicKey ed25519.PublicKey, now time.Time) (Record,error) {
	var out Record
	if len(caPublicKey)!=ed25519.PublicKeySize||len(raw)!=RDRSize{return out,ErrInvalidRDR}
	body,sig:=raw[:RDRBodySize],raw[RDRBodySize:]
	if body[0]!=1||body[1]!=1||binary.BigEndian.Uint16(body[2:4])!=0||body[52]!=1||body[53]!=6||body[96]!=1{return out,ErrInvalidRDR}
	for _,b:=range body[97:104]{if b!=0{return out,ErrInvalidRDR}}
	for _,b:=range body[128:RDRBodySize]{if b!=0{return out,ErrInvalidRDR}}
	message:=make([]byte,0,len("NLS-v1-RDR\x00")+len(body))
	message=append(message,[]byte("NLS-v1-RDR\x00")...)
	message=append(message,body...)
	if !ed25519.Verify(caPublicKey,message,sig){return out,fmt.Errorf("%w: signature verification failed",ErrInvalidRDR)}
	copy(out.RouterID[:],body[4:20])
	out.PublicKey=append(ed25519.PublicKey(nil),body[20:52]...)
	var ip [16]byte;copy(ip[:],body[54:70])
	addr:=netip.AddrFrom16(ip);port:=binary.BigEndian.Uint16(body[70:72])
	if addr.Is4In6()||port==0{return Record{},ErrInvalidRDR}
	out.Endpoint=netip.AddrPortFrom(addr,port)
	out.CertificateSerial=binary.BigEndian.Uint64(body[72:80])
	out.NotBefore=time.UnixMilli(int64(binary.BigEndian.Uint64(body[80:88]))).UTC()
	out.NotAfter=time.UnixMilli(int64(binary.BigEndian.Uint64(body[88:96]))).UTC()
	out.Generation=binary.BigEndian.Uint64(body[104:112])
	if out.CertificateSerial==0||out.Generation==0||!now.Before(out.NotAfter)||now.Before(out.NotBefore)||!out.NotAfter.After(out.NotBefore){return Record{},fmt.Errorf("%w: record outside validity window",ErrInvalidRDR)}
	out.Raw=append([]byte(nil),raw...)
	return out,nil
}

func cloneRecord(r Record) Record { r.PublicKey=append(ed25519.PublicKey(nil),r.PublicKey...);r.Raw=append([]byte(nil),r.Raw...);return r }
