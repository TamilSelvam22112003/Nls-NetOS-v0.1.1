package handshake

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/TamilSelvam22112003/Nls-NetOS-v0.1.1/internal/directory"
)

type PeerDirectory interface {
	LookupForHandshake(context.Context,[16]byte)(directory.Record,error)
}

type VIPProvider interface {
	Acquire(context.Context,netip.Addr,netip.Prefix,string,uint16)(netip.Addr,net.PacketConn,func()error,error)
}

type InitiatorConfig struct {
	LocalRecord directory.Record
	PrivateKey ed25519.PrivateKey
	CAPublicKey ed25519.PublicKey
	Directory PeerDirectory
	VIP VIPProvider
	WANAddress netip.Addr
	WANPrefix netip.Prefix
	Interface string
	Timeout time.Duration
}

type Session struct {
	LocalRouterID [16]byte
	PeerRouterID [16]byte
	LocalEndpoint netip.AddrPort
	PeerEndpoint netip.AddrPort
	SendKey [32]byte
	ReceiveKey [32]byte
	SendNoncePrefix [4]byte
	ReceiveNoncePrefix [4]byte
	CreatedAt time.Time
}

type keySchedule struct {
	hsI2R [32]byte
	hsR2I [32]byte
	finishR [32]byte
	dataI2R [32]byte
	dataR2I [32]byte
	nonceI2R [4]byte
	nonceR2I [4]byte
}

func deriveSchedule(dh []byte,th0 [32]byte)(keySchedule,error){
	var k keySchedule
	if len(dh)!=32||allZero(dh){return k,errors.New("invalid all-zero or malformed X25519 secret")}
	derive:=func(label string,n int)([]byte,error){info:=append([]byte(label),th0[:]...);out:=make([]byte,n);r:=hkdf.New(sha256.New,dh,th0[:],info);if _,err:=io.ReadFull(r,out);err!=nil{return nil,err};return out,nil}
	for _,item:=range []struct{label string;dst []byte}{{"NLS-v1 hs i2r",k.hsI2R[:]},{"NLS-v1 hs r2i",k.hsR2I[:]},{"NLS-v1 finish r",k.finishR[:]},{"NLS-v1 data i2r",k.dataI2R[:]},{"NLS-v1 data r2i",k.dataR2I[:]},{"NLS-v1 nonce i2r",k.nonceI2R[:]},{"NLS-v1 nonce r2i",k.nonceR2I[:]}}{
		out,err:=derive(item.label,len(item.dst));if err!=nil{return k,err};copy(item.dst,out)
	}
	return k,nil
}

func allZero(b []byte)bool{var v byte;for _,x:=range b{v|=x};return v==0}
func gcmFor(key []byte)(cipher.AEAD,error){block,err:=aes.NewCipher(key);if err!=nil{return nil,err};return cipher.NewGCM(block)}
var zeroHandshakeNonce = make([]byte,12)

func identityPlain(record directory.Record)[]byte{
	out:=make([]byte,64);copy(out[:16],record.RouterID[:]);binary.BigEndian.PutUint64(out[16:24],record.Generation);sum:=sha256.Sum256(record.Raw);copy(out[24:56],sum[:]);return out
}
func checkIdentityPlain(plain []byte,record directory.Record)bool{
	if len(plain)!=64{return false};if !bytes.Equal(plain[:16],record.RouterID[:])||binary.BigEndian.Uint64(plain[16:24])!=record.Generation||!bytes.Equal(plain[56:64],make([]byte,8)){return false}
	sum:=sha256.Sum256(record.Raw);return subtle.ConstantTimeCompare(plain[24:56],sum[:])==1
}
func signInput(context string,transcript,bodyWithoutSignature []byte)[]byte{
	h:=sha256.New();_,_=h.Write(transcript);_,_=h.Write(bodyWithoutSignature);sum:=h.Sum(nil)
	out:=make([]byte,0,len(context)+len(sum));out=append(out,[]byte(context)...);out=append(out,sum...);return out
}
func aad(typ byte,bodyLen int,prior [32]byte)[]byte{out:=frameHeader(typ,bodyLen);return append(out,prior[:]...)}
func localRecord(record directory.Record,private ed25519.PrivateKey,ca ed25519.PublicKey,now time.Time)(directory.Record,error){
	if len(private)!=ed25519.PrivateKeySize{return directory.Record{},errors.New("router Ed25519 private key must be 64 bytes")}
	verified,err:=directory.VerifyRDR(record.Raw,ca,now);if err!=nil{return directory.Record{},fmt.Errorf("local RDR invalid: %w",err)}
	if verified.RouterID!=record.RouterID||!bytes.Equal(verified.PublicKey,private.Public().(ed25519.PublicKey)){return directory.Record{},ErrIdentity}
	return verified,nil
}

func Initiate(ctx context.Context,cfg InitiatorConfig,peerID [16]byte,peerEndpoint netip.AddrPort)(session Session,retErr error){
	if cfg.Directory==nil||cfg.VIP==nil{return session,errors.New("online directory and temporary vIP provider are required")}
	if !peerEndpoint.IsValid()||!peerEndpoint.Addr().Is6()||peerEndpoint.Addr().Is4In6()||peerEndpoint.Port()==0{return session,errors.New("peer endpoint must be IPv6 with a nonzero UDP port")}
	if cfg.Timeout<=0{cfg.Timeout=10*time.Second}
	ctx,cancel:=context.WithTimeout(ctx,cfg.Timeout);defer cancel()
	now:=time.Now()
	local,err:=localRecord(cfg.LocalRecord,cfg.PrivateKey,cfg.CAPublicKey,now);if err!=nil{return session,err}
	vip,conn,release,err:=cfg.VIP.Acquire(ctx,cfg.WANAddress,cfg.WANPrefix,cfg.Interface,local.Endpoint.Port());if err!=nil{return session,err}
	if release==nil{return session,errors.New("vIP provider returned no cleanup function")}
	released:=false
	defer func(){if !released{if e:=release();retErr==nil&&e!=nil{retErr=e}}}()
	if !vip.Is6()||vip.Is4In6(){return session,errors.New("temporary vIP must be IPv6")}
	if cfg.WANAddress.IsValid()&&local.Endpoint.Addr()!=cfg.WANAddress{return session,errors.New("local RDR endpoint must match configured WAN address")}
	localAddr,err:=netAddrPort(conn.LocalAddr());if err!=nil{return session,err}
	if localAddr.Addr()!=vip||localAddr.Port()!=local.Endpoint.Port(){return session,fmt.Errorf("temporary socket must bind vIP %s and advertised UDP port %d",vip,local.Endpoint.Port())}
	watchDone:=make(chan struct{});defer close(watchDone)
	go func(){select{case <-ctx.Done():_ = conn.SetReadDeadline(time.Now());case <-watchDone:}}()

	curve:=ecdh.X25519();ephPriv,err:=curve.GenerateKey(rand.Reader);if err!=nil{return session,err}
	var f m1Fields
	if _,err=rand.Read(f.Nonce[:]);err!=nil{return session,err}
	f.InitiatorID=local.RouterID;f.DestinationID=peerID;copy(f.Ephemeral[:],ephPriv.PublicKey().Bytes())
	initial:=buildM1(f)
	cookieRaw,err:=sendWait(ctx,conn,peerEndpoint,initial,3,time.Second,func(raw []byte)bool{
		m,e:=parseFrame(raw,TypeM1Cookie,M1CookieBodySize);if e!=nil{return false}
		return subtle.ConstantTimeCompare(m.Body[:32],f.Nonce[:])==1
	})
	if err!=nil{return session,fmt.Errorf("M1 cookie challenge: %w",err)}
	cm,_:=parseFrame(cookieRaw,TypeM1Cookie,M1CookieBodySize)
	copy(f.Cookie[:],cm.Body[32:48]);f.CookiePresent=true
	cookieM1:=buildM1(f)
	transcript:=append(append(append([]byte{},initial...),cookieRaw...),cookieM1...)
	th0:=transcriptHash(transcript)
	m2raw,err:=sendOnceWait(ctx,conn,peerEndpoint,cookieM1,3*time.Second,func(raw []byte)bool{_,e:=parseFrame(raw,TypeM2,M2BodySize);return e==nil})
	if err!=nil{return session,fmt.Errorf("M2: %w",err)}
	m2,err:=parseFrame(m2raw,TypeM2,M2BodySize);if err!=nil{return session,err}
	if subtle.ConstantTimeCompare(m2.Body[64:96],th0[:])!=1{return session,ErrTranscript}
	peer,err:=cfg.Directory.LookupForHandshake(ctx,peerID);if err!=nil{return session,fmt.Errorf("fresh Router-CA lookup: %w",err)}
	if peer.RouterID!=peerID||peer.Endpoint!=peerEndpoint||peer.NotBefore.After(time.Now())||!time.Now().Before(peer.NotAfter){return session,directory.ErrInvalidRDR}
	if len(peer.Raw)!=directory.RDRSize{return session,directory.ErrInvalidRDR}
	peerPub,err:=curve.NewPublicKey(m2.Body[32:64]);if err!=nil{return session,ErrMalformed}
	dh,err:=ephPriv.ECDH(peerPub);if err!=nil||allZero(dh){return session,errors.New("invalid X25519 shared secret")}
	keys,err:=deriveSchedule(dh,th0);if err!=nil{return session,err}
	if binary.BigEndian.Uint16(m2.Body[96:98])!=80||binary.BigEndian.Uint16(m2.Body[178:180])!=64{return session,ErrMalformed}
	sigInput:=signInput("NLS-v1-M2-SIG\x00",transcript,m2.Body[:180])
	if !ed25519.Verify(peer.PublicKey,sigInput,m2.Body[180:244]){return session,ErrSignature}
	gcm,err:=gcmFor(keys.hsR2I[:]);if err!=nil{return session,err}
	plain,err:=gcm.Open(nil,zeroHandshakeNonce,m2.Body[98:178],aad(TypeM2,M2BodySize,th0))
	if err!=nil{return session,ErrAEAD}
	if !checkIdentityPlain(plain,peer){return session,ErrIdentity}
	transcript=append(transcript,m2raw...)
	thPriorM3:=transcriptHash(transcript)
	m3body:=make([]byte,M3BodySize);copy(m3body[:32],thPriorM3[:]);binary.BigEndian.PutUint16(m3body[32:34],80)
	gcm,err=gcmFor(keys.hsI2R[:]);if err!=nil{return session,err}
	encrypted:=gcm.Seal(nil,zeroHandshakeNonce,identityPlain(local),aad(TypeM3,M3BodySize,thPriorM3))
	copy(m3body[34:114],encrypted)
	sig:=ed25519.Sign(cfg.PrivateKey,signInput("NLS-v1-M3-SIG\x00",transcript,m3body[:114]));copy(m3body[114:],sig)
	m3raw:=frame(TypeM3,m3body)
	m4raw,err:=sendOnceWait(ctx,conn,peerEndpoint,m3raw,3*time.Second,func(raw []byte)bool{_,e:=parseFrame(raw,TypeM4,M4BodySize);return e==nil})
	if err!=nil{return session,fmt.Errorf("M4: %w",err)}
	m4,err:=parseFrame(m4raw,TypeM4,M4BodySize);if err!=nil{return session,err}
	transcript=append(transcript,m3raw...)
	thM4:=transcriptHash(transcript)
	if subtle.ConstantTimeCompare(m4.Body[:32],thM4[:])!=1{return session,ErrTranscript}
	mac:=hmac.New(sha256.New,keys.finishR[:]);_,_=mac.Write([]byte("NLS-v1-M4-FIN\x00"));_,_=mac.Write(thM4[:])
	if !hmac.Equal(mac.Sum(nil),m4.Body[32:64]){return session,ErrAEAD}
	if err=release();err!=nil{return session,fmt.Errorf("remove temporary vIP after M4: %w",err)}
	released=true
	session=Session{LocalRouterID:local.RouterID,PeerRouterID:peer.RouterID,LocalEndpoint:local.Endpoint,PeerEndpoint:peer.Endpoint,SendKey:keys.dataI2R,ReceiveKey:keys.dataR2I,SendNoncePrefix:keys.nonceI2R,ReceiveNoncePrefix:keys.nonceR2I,CreatedAt:time.Now().UTC()}
	return session,nil
}

func sendOnceWait(ctx context.Context,conn net.PacketConn,peer netip.AddrPort,request []byte,timeout time.Duration,accept func([]byte)bool)([]byte,error){
	if err:=ctx.Err();err!=nil{return nil,err}
	dst:=&net.UDPAddr{IP:net.IP(peer.Addr().AsSlice()),Port:int(peer.Port()),Zone:peer.Addr().Zone()}
	if _,err:=conn.WriteTo(request,dst);err!=nil{return nil,err}
	deadline:=time.Now().Add(timeout);if d,ok:=ctx.Deadline();ok&&d.Before(deadline){deadline=d}
	_ = conn.SetReadDeadline(deadline)
	buf:=make([]byte,2048)
	for{
		n,from,err:=conn.ReadFrom(buf)
		if err!=nil{if ne,ok:=err.(net.Error);ok&&ne.Timeout(){return nil,ErrHandshakeTimeout};if ctx.Err()!=nil{return nil,ctx.Err()};return nil,err}
		got,e:=netAddrPort(from);if e!=nil||got!=peer{continue}
		raw:=append([]byte(nil),buf[:n]...)
		if accept(raw){return raw,nil}
	}
}

func sendWait(ctx context.Context,conn net.PacketConn,peer netip.AddrPort,request []byte,attempts int,interval time.Duration,accept func([]byte)bool)([]byte,error){
	dst:=&net.UDPAddr{IP:net.IP(peer.Addr().AsSlice()),Port:int(peer.Port()),Zone:peer.Addr().Zone()}
	buf:=make([]byte,2048)
	for i:=0;i<attempts;i++{
		if err:=ctx.Err();err!=nil{return nil,err}
		if _,err:=conn.WriteTo(request,dst);err!=nil{return nil,err}
		deadline:=time.Now().Add(interval);if d,ok:=ctx.Deadline();ok&&d.Before(deadline){deadline=d}
		_ = conn.SetReadDeadline(deadline)
		for{
			n,from,err:=conn.ReadFrom(buf)
			if err!=nil{if ne,ok:=err.(net.Error);ok&&ne.Timeout(){break};if ctx.Err()!=nil{return nil,ctx.Err()};return nil,err}
			got,e:=netAddrPort(from);if e!=nil||got!=peer{continue}
			raw:=append([]byte(nil),buf[:n]...)
			if accept(raw){return raw,nil}
		}
	}
	return nil,ErrHandshakeTimeout
}

func netAddrPort(a net.Addr)(netip.AddrPort,error){
	u,ok:=a.(*net.UDPAddr);if !ok{return netip.AddrPort{},fmt.Errorf("expected UDP address, got %T",a)}
	ip,ok:=netip.AddrFromSlice(u.IP);if !ok{return netip.AddrPort{},errors.New("invalid UDP IP address")}
	if ip.Is4In6(){ip=ip.Unmap()}
	return netip.AddrPortFrom(ip,uint16(u.Port)),nil
}

type ResponderConfig struct {
	LocalRecord directory.Record
	PrivateKey ed25519.PrivateKey
	CAPublicKey ed25519.PublicKey
	Directory PeerDirectory
	Cookies *CookieManager
	Limiter *M1Limiter
	MaxPending int
	MaxPendingPerPrefix int
	PendingTTL time.Duration
	OnEstablished func(Session)
	Now func()time.Time
}

type pendingKey struct { Source netip.AddrPort; Prior [32]byte }
type pendingHandshake struct {
	fields m1Fields
	ephemeral *ecdh.PrivateKey
	keys keySchedule
	th0 [32]byte
	transcript []byte
	source netip.AddrPort
	created time.Time
}

type Responder struct {
	cfg ResponderConfig
	local directory.Record
	mu sync.Mutex
	pending map[pendingKey]pendingHandshake
}

func NewResponder(cfg ResponderConfig)(*Responder,error){
	if cfg.Directory==nil||cfg.Cookies==nil||cfg.Limiter==nil{return nil,errors.New("responder requires online directory, cookie manager, and configured M1 limiter")}
	if cfg.MaxPending<1||cfg.MaxPendingPerPrefix<1||cfg.PendingTTL<=0{return nil,errors.New("pending state limits and pending TTL must be configured explicitly")}
	if cfg.Now==nil{cfg.Now=time.Now}
	local,err:=localRecord(cfg.LocalRecord,cfg.PrivateKey,cfg.CAPublicKey,cfg.Now());if err!=nil{return nil,err}
	return &Responder{cfg:cfg,local:local,pending:make(map[pendingKey]pendingHandshake)},nil
}

func (r *Responder) Serve(ctx context.Context,conn net.PacketConn,ingress string)error{
	if conn==nil{return errors.New("UDP connection required")}
	localAddr,err:=netAddrPort(conn.LocalAddr());if err!=nil{return err}
	if !localAddr.Addr().Is6()||localAddr.Addr().Is4In6(){return errors.New("responder socket must bind a specific IPv6 endpoint")}
	if localAddr!=r.local.Endpoint{return errors.New("responder socket must match the local RDR endpoint")}
	buf:=make([]byte,2048)
	done:=make(chan struct{});defer close(done)
	go func(){select{case <-ctx.Done():_ = conn.SetReadDeadline(time.Now());case <-done:}}()
	for{
		if err:=ctx.Err();err!=nil{return nil}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n,from,err:=conn.ReadFrom(buf)
		if err!=nil{if ctx.Err()!=nil{return nil};if ne,ok:=err.(net.Error);ok&&ne.Timeout(){continue};return err}
		source,err:=netAddrPort(from);if err!=nil{continue}
		response,established,completedKey,err:=r.dispatch(ctx,append([]byte(nil),buf[:n]...),source,localAddr,ingress)
		if err!=nil||len(response)==0{continue}
		if _,err=conn.WriteTo(response,from);err!=nil{continue}
		if established!=nil&&completedKey!=nil{
			r.mu.Lock();delete(r.pending,*completedKey);r.mu.Unlock()
			if r.cfg.OnEstablished!=nil{r.cfg.OnEstablished(*established)}
		}
	}
}

func (r *Responder) HandleDatagram(ctx context.Context,raw []byte,source,destination netip.AddrPort,ingress string)([]byte,error){
	now:=r.cfg.Now()
	m1,err:=parseM1(raw);if err!=nil{return nil,nil}
	if m1.DestinationID!=r.local.RouterID{return nil,nil}
	if !r.cfg.Limiter.Allow(now,source.Addr(),ingress){return nil,nil}
	if !m1.CookiePresent{
		cookie,bucket,err:=r.cfg.Cookies.Issue(source,destination,m1.InitiatorID,m1.DestinationID,m1.Nonce,now);if err!=nil{return nil,err}
		body:=make([]byte,M1CookieBodySize);copy(body[:32],m1.Nonce[:]);copy(body[32:48],cookie[:]);binary.BigEndian.PutUint32(body[48:52],bucket)
		return frame(TypeM1Cookie,body),nil
	}
	bucket,ok:=r.cfg.Cookies.VerifyBucket(source,destination,m1.InitiatorID,m1.DestinationID,m1.Nonce,m1.Cookie,now);if !ok{return nil,nil}
	r.mu.Lock()
	r.expireLocked(now)
	if len(r.pending)>=r.cfg.MaxPending||r.countPrefixLocked(source.Addr())>=r.cfg.MaxPendingPerPrefix{r.mu.Unlock();return nil,nil}
	r.mu.Unlock()
	curve:=ecdh.X25519();eph,err:=curve.GenerateKey(rand.Reader);if err!=nil{return nil,err}
	var responderNonce [32]byte;if _,err=rand.Read(responderNonce[:]);err!=nil{return nil,err}
	peerPub,err:=curve.NewPublicKey(m1.Ephemeral[:]);if err!=nil{return nil,nil}
	dh,err:=eph.ECDH(peerPub);if err!=nil||allZero(dh){return nil,nil}
	initialFields:=m1;initialFields.CookiePresent=false;initialFields.Cookie=[16]byte{}
	initial:=buildM1(initialFields)
	cookieBody:=make([]byte,M1CookieBodySize);copy(cookieBody[:32],m1.Nonce[:]);copy(cookieBody[32:48],m1.Cookie[:]);binary.BigEndian.PutUint32(cookieBody[48:52],bucket)
	cookieRaw:=frame(TypeM1Cookie,cookieBody)
	cookieM1:=buildM1(m1)
	transcript:=append(append(append([]byte{},initial...),cookieRaw...),cookieM1...)
	th0:=transcriptHash(transcript)
	keys,err:=deriveSchedule(dh,th0);if err!=nil{return nil,err}
	body:=make([]byte,M2BodySize);copy(body[:32],responderNonce[:]);copy(body[32:64],eph.PublicKey().Bytes());copy(body[64:96],th0[:]);binary.BigEndian.PutUint16(body[96:98],80)
	gcm,err:=gcmFor(keys.hsR2I[:]);if err!=nil{return nil,err}
	copy(body[98:178],gcm.Seal(nil,zeroHandshakeNonce,identityPlain(r.local),aad(TypeM2,M2BodySize,th0)))
	binary.BigEndian.PutUint16(body[178:180],64)
	sig:=ed25519.Sign(r.cfg.PrivateKey,signInput("NLS-v1-M2-SIG\x00",transcript,body[:180]));copy(body[180:],sig)
	m2raw:=frame(TypeM2,body);transcript=append(transcript,m2raw...)
	thPrior:=transcriptHash(transcript)
	key:=pendingKey{Source:source,Prior:thPrior}
	r.mu.Lock();r.expireLocked(now)
	if len(r.pending)>=r.cfg.MaxPending||r.countPrefixLocked(source.Addr())>=r.cfg.MaxPendingPerPrefix{r.mu.Unlock();return nil,nil}
	r.pending[key]=pendingHandshake{fields:m1,ephemeral:eph,keys:keys,th0:th0,transcript:transcript,source:source,created:now}
	r.mu.Unlock()
	return m2raw,nil
}

func (r *Responder) handleM3(ctx context.Context,raw []byte,source netip.AddrPort)([]byte,*Session,*pendingKey,error){
	m3,err:=parseFrame(raw,TypeM3,M3BodySize);if err!=nil{return nil,nil,nil,nil}
	var prior [32]byte;copy(prior[:],m3.Body[:32])
	key:=pendingKey{Source:source,Prior:prior}
	now:=r.cfg.Now()
	r.mu.Lock();r.expireLocked(now);pending,ok:=r.pending[key];r.mu.Unlock()
	if !ok{return nil,nil,nil,nil}
	completed:=false
	defer func(){if !completed{r.mu.Lock();delete(r.pending,key);r.mu.Unlock()}}()
	expectedPrior:=transcriptHash(pending.transcript);if subtle.ConstantTimeCompare(prior[:],expectedPrior[:])!=1{return nil,nil,nil,nil}
	peer,err:=r.cfg.Directory.LookupForHandshake(ctx,pending.fields.InitiatorID)
	if err!=nil{return nil,nil,nil,nil}
	if peer.RouterID!=pending.fields.InitiatorID||peer.Endpoint.Port()!=source.Port()||peer.NotBefore.After(now)||!now.Before(peer.NotAfter){return nil,nil,nil,nil}
	if binary.BigEndian.Uint16(m3.Body[32:34])!=80{return nil,nil,nil,nil}
	sigInput:=signInput("NLS-v1-M3-SIG\x00",pending.transcript,m3.Body[:114])
	if !ed25519.Verify(peer.PublicKey,sigInput,m3.Body[114:178]){return nil,nil,nil,nil}
	gcm,err:=gcmFor(pending.keys.hsI2R[:]);if err!=nil{return nil,nil,nil,err}
	plain,err:=gcm.Open(nil,zeroHandshakeNonce,m3.Body[34:114],aad(TypeM3,M3BodySize,prior));if err!=nil{return nil,nil,nil,nil}
	if !checkIdentityPlain(plain,peer){return nil,nil,nil,nil}
	transcript:=append(append([]byte{},pending.transcript...),raw...)
	thM4:=transcriptHash(transcript)
	body:=make([]byte,M4BodySize);copy(body[:32],thM4[:])
	mac:=hmac.New(sha256.New,pending.keys.finishR[:]);_,_=mac.Write([]byte("NLS-v1-M4-FIN\x00"));_,_=mac.Write(thM4[:]);copy(body[32:],mac.Sum(nil))
	session:=Session{LocalRouterID:r.local.RouterID,PeerRouterID:peer.RouterID,LocalEndpoint:r.local.Endpoint,PeerEndpoint:peer.Endpoint,SendKey:pending.keys.dataR2I,ReceiveKey:pending.keys.dataI2R,SendNoncePrefix:pending.keys.nonceR2I,ReceiveNoncePrefix:pending.keys.nonceI2R,CreatedAt:now.UTC()}
	completed=true
	return frame(TypeM4,body),&session,&key,nil
}

func (r *Responder) expireLocked(now time.Time){
	for key,p:=range r.pending{if now.Before(p.created)||now.Sub(p.created)>r.cfg.PendingTTL{delete(r.pending,key)}}
}
func (r *Responder) countPrefixLocked(addr netip.Addr)int{
	prefix:=netip.PrefixFrom(addr,64).Masked();n:=0
	for key:=range r.pending{if key.Source.Addr().IsValid()&&netip.PrefixFrom(key.Source.Addr(),64).Masked()==prefix{n++}}
	return n
}

// Dispatch routes M3 through authentication and returns a session only after a
// valid M3; Serve installs that session only after M4 has been written.
func (r *Responder) dispatch(ctx context.Context,raw []byte,source,destination netip.AddrPort,ingress string)([]byte,*Session,*pendingKey,error){
	if len(raw)>=2&&raw[0]==WireVersion&&raw[1]==TypeM3{return r.handleM3(ctx,raw,source)}
	response,err:=r.HandleDatagram(ctx,raw,source,destination,ingress)
	return response,nil,nil,err
}
