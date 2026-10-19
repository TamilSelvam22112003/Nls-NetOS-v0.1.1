package handshake

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TamilSelvam22112003/Nls-NetOS-v0.1.1/internal/directory"
)

type testVIPProvider struct {
	conn net.PacketConn
	vip netip.Addr
	mutateType byte
	released atomic.Int32
}
func (p *testVIPProvider) Acquire(_ context.Context,_ netip.Addr,_ netip.Prefix,_ string,port uint16)(netip.Addr,net.PacketConn,func()error,error){
	if p.conn==nil{return netip.Addr{},nil,nil,errors.New("test socket missing")}
	got,err:=netAddrPort(p.conn.LocalAddr());if err!=nil{return netip.Addr{},nil,nil,err}
	if got.Port()!=port{return netip.Addr{},nil,nil,errors.New("test socket port does not match RDR")}
	var c net.PacketConn=p.conn
	if p.mutateType!=0{c=&mutatingConn{PacketConn:c,typ:p.mutateType}}
	return p.vip,c,func()error{p.released.Add(1);return p.conn.Close()},nil
}

type mutatingConn struct { net.PacketConn; typ byte }
func (c *mutatingConn) WriteTo(b []byte,addr net.Addr)(int,error){
	copyB:=append([]byte(nil),b...)
	if len(copyB)>HeaderSize&&copyB[0]==WireVersion&&copyB[1]==c.typ{copyB[len(copyB)-1]^=1}
	return c.PacketConn.WriteTo(copyB,addr)
}

type pair struct {
	initID [16]byte
	respID [16]byte
	initRecord directory.Record
	respRecord directory.Record
	initPriv ed25519.PrivateKey
	respPriv ed25519.PrivateKey
	caPub ed25519.PublicKey
	initVIP *testVIPProvider
	respConn *net.UDPConn
	resp *Responder
	initDir *directory.Cache
	cancel context.CancelFunc
	established chan Session
}

func makeRDR(t *testing.T,caPriv ed25519.PrivateKey,id [16]byte,routerPub ed25519.PublicKey,endpoint netip.AddrPort,now time.Time,notBefore,notAfter time.Time)(directory.Record,[]byte){
	t.Helper()
	body:=make([]byte,directory.RDRBodySize);body[0],body[1]=1,1;copy(body[4:20],id[:]);copy(body[20:52],routerPub)
	body[52],body[53]=1,6;ip:=endpoint.Addr().As16();copy(body[54:70],ip[:]);binary.BigEndian.PutUint16(body[70:72],uint16(endpoint.Port()))
	binary.BigEndian.PutUint64(body[72:80],1);binary.BigEndian.PutUint64(body[80:88],uint64(notBefore.UnixMilli()));binary.BigEndian.PutUint64(body[88:96],uint64(notAfter.UnixMilli()))
	body[96]=1;binary.BigEndian.PutUint64(body[104:112],1);if _,err:=rand.Read(body[112:128]);err!=nil{t.Fatal(err)}
	msg:=append([]byte("NLS-v1-RDR\x00"),body...);raw:=append(body,ed25519.Sign(caPriv,msg)...)
	rec,err:=directory.VerifyRDR(raw,caPriv.Public().(ed25519.PublicKey),now);if err!=nil{t.Fatal(err)}
	return rec,raw
}

func testLimiter(t *testing.T) *M1Limiter{
	t.Helper();m,err:=NewM1Limiter(LimitConfig{GlobalRate:1000,GlobalBurst:100,PerInterfaceRate:1000,PerInterfaceBurst:100,PerPrefixRate:1000,PerPrefixBurst:100,MaxTrackedPrefixes:128,PrefixIdleTTL:time.Minute,Interfaces:[]string{"lo","eth0","eth1"}});if err!=nil{t.Fatal(err)};return m
}

func newPair(t *testing.T,lookupMode string,tamper byte)*pair{
	t.Helper();now:=time.Now().UTC()
	caPub,caPriv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	initPub,initPriv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	respPub,respPriv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	var initID,respID [16]byte;initID[0]=0x11;respID[0]=0x22
	loop:=netip.IPv6Loopback()
	respUDP,err:=net.ListenUDP("udp6",&net.UDPAddr{IP:net.IP(loop.AsSlice()),Port:0});if err!=nil{t.Fatal(err)}
	respEP,err:=netAddrPort(respUDP.LocalAddr());if err!=nil{t.Fatal(err)}
	respRecord,respRaw:=makeRDR(t,caPriv,respID,respPub,respEP,now,now.Add(-time.Minute),now.Add(time.Hour))
	initUDP,err:=net.ListenUDP("udp6",&net.UDPAddr{IP:net.IP(loop.AsSlice()),Port:0});if err!=nil{_ = respUDP.Close();t.Fatal(err)}
	initEP,err:=netAddrPort(initUDP.LocalAddr());if err!=nil{t.Fatal(err)}
	initRecord,initRaw:=makeRDR(t,caPriv,initID,initPub,initEP,now,now.Add(-time.Minute),now.Add(time.Hour))
	vip:=&testVIPProvider{conn:initUDP,vip:loop,mutateType:tamper}
	respLookup:=func(_ context.Context,id [16]byte)(uint16,[]byte,error){if id==initID{return directory.LookupFound,initRaw,nil};return directory.LookupUnknown,nil,nil}
	respDir,err:=directory.NewCache(caPub,time.Minute,respLookup);if err!=nil{t.Fatal(err)}
	var cookieNow=time.Now
	cookies,err:=NewCookieManager(cookieNow);if err!=nil{t.Fatal(err)}
	respCfg:=ResponderConfig{LocalRecord:respRecord,PrivateKey:respPriv,CAPublicKey:caPub,Directory:respDir,Cookies:cookies,Limiter:testLimiter(t),MaxPending:64,MaxPendingPerPrefix:8,PendingTTL:3*time.Second,Now:time.Now}
	established:=make(chan Session,1);respCfg.OnEstablished=func(s Session){established<-s}
	resp,err:=NewResponder(respCfg);if err!=nil{t.Fatal(err)}
	lookup:=func(_ context.Context,id [16]byte)(uint16,[]byte,error){
		if id!=respID{return directory.LookupUnknown,nil,nil}
		switch lookupMode{
		case "revoked":return directory.LookupRevoked,nil,nil
		case "stale":
			body:=append([]byte(nil),respRaw[:directory.RDRBodySize]...)
			binary.BigEndian.PutUint64(body[80:88],uint64(now.Add(-2*time.Hour).UnixMilli()))
			binary.BigEndian.PutUint64(body[88:96],uint64(now.Add(-time.Hour).UnixMilli()))
			msg:=append([]byte("NLS-v1-RDR\\x00"),body...)
			raw:=append(body,ed25519.Sign(caPriv,msg)...)
			return directory.LookupFound,raw,nil
		default:return directory.LookupFound,respRaw,nil
		}
	}
	initDir,err:=directory.NewCache(caPub,time.Minute,lookup);if err!=nil{t.Fatal(err)}
	ctx,cancel:=context.WithCancel(context.Background())
	serverConn:=net.PacketConn(respUDP)
	if tamper==TypeM2{serverConn=&mutatingConn{PacketConn:serverConn,typ:TypeM2};vip.mutateType=0}
	go func(){_ = resp.Serve(ctx,serverConn,"lo")}()
	return &pair{initID:initID,respID:respID,initRecord:initRecord,respRecord:respRecord,initPriv:initPriv,respPriv:respPriv,caPub:caPub,initVIP:vip,respConn:respUDP,resp:resp,initDir:initDir,cancel:cancel,established:established}
}

func (p *pair) close(){p.cancel();_ = p.respConn.Close();if p.initVIP!=nil{_ = p.initVIP.conn.Close()}}

func runPair(t *testing.T,lookupMode string,tamper byte)(Session,*pair,error){
	t.Helper();p:=newPair(t,lookupMode,tamper)
	cfg:=InitiatorConfig{LocalRecord:p.initRecord,PrivateKey:p.initPriv,CAPublicKey:p.caPub,Directory:p.initDir,VIP:p.initVIP,WANAddress:netip.IPv6Loopback(),WANPrefix:netip.MustParsePrefix("::1/128"),Interface:"lo",Timeout:10*time.Second}
	s,err:=Initiate(context.Background(),cfg,p.respID,p.respRecord.Endpoint)
	return s,p,err
}

func TestSuccessfulM1M4HandshakeAndTemporaryVIPLifecycle(t *testing.T){
	s,p,err:=runPair(t,"valid",0);defer p.close();if err!=nil{t.Fatal(err)}
	if s.PeerRouterID!=p.respID||s.LocalRouterID!=p.initID||s.PeerEndpoint!=p.respRecord.Endpoint{t.Fatalf("wrong initiator session: %#v",s)}
	if p.initVIP.released.Load()!=1{t.Fatalf("temporary vIP cleanup count=%d, want 1",p.initVIP.released.Load())}
	select{case peer:=<-p.established:
		if peer.SendKey!=s.ReceiveKey||peer.ReceiveKey!=s.SendKey||peer.SendNoncePrefix!=s.ReceiveNoncePrefix||peer.ReceiveNoncePrefix!=s.SendNoncePrefix{t.Fatal("directional key schedule differs between peers")}
		if peer.PeerEndpoint!=p.initRecord.Endpoint{t.Fatalf("responder did not switch to initiator's real endpoint: %#v",peer.PeerEndpoint)}
	case <-time.After(time.Second):t.Fatal("responder did not establish session")}
}

func TestTamperedM2Rejected(t *testing.T){
	_,p,err:=runPair(t,"valid",TypeM2);defer p.close()
	if !errors.Is(err,ErrSignature){t.Fatalf("tampered M2 error=%v, want ErrSignature",err)}
	if p.initVIP.released.Load()!=1{t.Fatal("temporary vIP not removed after failed handshake")}
}

func TestTamperedM3Rejected(t *testing.T){
	_,p,err:=runPair(t,"valid",TypeM3);defer p.close()
	if !errors.Is(err,ErrHandshakeTimeout){t.Fatalf("tampered M3 error=%v, want timeout after silent rejection",err)}
	select{case <-p.established:t.Fatal("responder established a tampered M3");default:}
}

func TestRevokedPeerRejected(t *testing.T){
	_,p,err:=runPair(t,"revoked",0);defer p.close()
	if !errors.Is(err,directory.ErrRevoked){t.Fatalf("revoked peer error=%v",err)}
	if p.initVIP.released.Load()!=1{t.Fatal("temporary vIP not removed on revocation")}
}

func TestStaleRDRRejected(t *testing.T){
	_,p,err:=runPair(t,"stale",0);defer p.close()
	if !errors.Is(err,directory.ErrInvalidRDR){t.Fatalf("stale RDR error=%v",err)}
	if p.initVIP.released.Load()!=1{t.Fatal("temporary vIP not removed on stale RDR")}
}

func TestM1DoSLimitsAndNoStateBeforeCookie(t *testing.T){
	for _,tc:=range []struct{name string;global,iface,prefix float64;globalBurst,ifaceBurst,prefixBurst float64;src1,src2 string;ingress1,ingress2 string}{
		{name:"global",global:100,iface:100,prefix:100,globalBurst:1,ifaceBurst:100,prefixBurst:100,src1:"2001:db8:1::1",src2:"2001:db8:2::1",ingress1:"eth0",ingress2:"eth1"},
		{name:"interface",global:100,iface:100,prefix:100,globalBurst:100,ifaceBurst:1,prefixBurst:100,src1:"2001:db8:1::1",src2:"2001:db8:2::1",ingress1:"eth0",ingress2:"eth0"},
		{name:"source /64",global:100,iface:100,prefix:100,globalBurst:100,ifaceBurst:100,prefixBurst:1,src1:"2001:db8:1::1",src2:"2001:db8:1::2",ingress1:"eth0",ingress2:"eth0"},
	}{
		t.Run(tc.name,func(t *testing.T){
			now:=time.Unix(1800000000,0);caPub,caPriv,_:=ed25519.GenerateKey(rand.Reader);routerPub,routerPriv,_:=ed25519.GenerateKey(rand.Reader);var rid [16]byte;rid[0]=9
			ep:=netip.MustParseAddrPort("[2001:db8::10]:4444");record,_:=makeRDR(t,caPriv,rid,routerPub,ep,now,now.Add(-time.Minute),now.Add(time.Hour))
			lookup:=func(context.Context,[16]byte)(uint16,[]byte,error){return directory.LookupUnknown,nil,nil}
			dir,_:=directory.NewCache(caPub,time.Minute,lookup);cookies,_:=NewCookieManager(func()time.Time{return now})
			limiter,err:=NewM1Limiter(LimitConfig{GlobalRate:tc.global,GlobalBurst:tc.globalBurst,PerInterfaceRate:tc.iface,PerInterfaceBurst:tc.ifaceBurst,PerPrefixRate:tc.prefix,PerPrefixBurst:tc.prefixBurst,MaxTrackedPrefixes:32,PrefixIdleTTL:time.Minute,Interfaces:[]string{"eth0","eth1"}});if err!=nil{t.Fatal(err)}
			r,err:=NewResponder(ResponderConfig{LocalRecord:record,PrivateKey:routerPriv,CAPublicKey:caPub,Directory:dir,Cookies:cookies,Limiter:limiter,MaxPending:8,MaxPendingPerPrefix:4,PendingTTL:3*time.Second,Now:func()time.Time{return now}});if err!=nil{t.Fatal(err)}
			var initiatorID [16]byte;initiatorID[0]=7;var eph [32]byte;eph[0]=1;var nonce [32]byte;nonce[0]=2
			first:=buildM1(m1Fields{Nonce:nonce,InitiatorID:initiatorID,DestinationID:rid,Ephemeral:eph})
			s1:=netip.MustParseAddrPort("["+tc.src1+"]:50000");s2:=netip.MustParseAddrPort("["+tc.src2+"]:50000")
			if got,_:=r.HandleDatagram(context.Background(),first,s1,ep,tc.ingress1);len(got)!=M1CookieFrameSize{t.Fatalf("first M1 did not receive cookie: len=%d",len(got))}
			if len(r.pending)!=0{t.Fatal("responder allocated state before cookie")}
			if got,_:=r.HandleDatagram(context.Background(),first,s2,ep,tc.ingress2);len(got)!=0{t.Fatalf("second M1 should be silently rate-limited, got %d bytes",len(got))}
			if len(r.pending)!=0{t.Fatal("rate-limited M1 allocated state")}
		})
	}
}

func TestCookieReconstructsStatelessTranscriptAcrossPreviousBucket(t *testing.T){
	now:=time.Unix(1800000000,0);clock:=now
	c,err:=NewCookieManager(func()time.Time{return clock});if err!=nil{t.Fatal(err)}
	src:=netip.MustParseAddrPort("[2001:db8:1::1]:45000");dst:=netip.MustParseAddrPort("[2001:db8:2::1]:45000")
	var srcID,dstID [16]byte;srcID[0]=1;dstID[0]=2;var nonce [32]byte;nonce[0]=3
	cookie,bucket,err:=c.Issue(src,dst,srcID,dstID,nonce,now);if err!=nil{t.Fatal(err)}
	clock=now.Add(10*time.Minute)
	if got,ok:=c.VerifyBucket(src,dst,srcID,dstID,nonce,cookie,clock);!ok||got!=bucket{t.Fatal("previous bucket cookie should remain valid")}
	if c.Verify(src,dst,srcID,dstID,nonce,cookie,clock.Add(10*time.Minute)){t.Fatal("expired cookie accepted")}
}

func TestM1CookieChallengeSizeAndPadding(t *testing.T){
	var f m1Fields;f.Nonce[0]=1;f.InitiatorID[0]=2;f.DestinationID[0]=3;f.Ephemeral[0]=4
	initial:=buildM1(f);if len(initial)!=M1FrameSize{t.Fatalf("M1 size=%d",len(initial))}
	parsed,err:=parseM1(initial);if err!=nil||parsed.CookiePresent{t.Fatalf("initial M1 parse: %#v %v",parsed,err)}
	f.CookiePresent=true;f.Cookie[0]=5;cookieM1:=buildM1(f);parsed,err=parseM1(cookieM1);if err!=nil||!parsed.CookiePresent||!bytes.Equal(parsed.Cookie[:],f.Cookie[:]){t.Fatalf("cookie M1 parse: %#v %v",parsed,err)}
	if len(frame(TypeM1Cookie,make([]byte,M1CookieBodySize)))!=M1CookieFrameSize{t.Fatal("M1_COOKIE framing size mismatch")}
}

func TestCookieM1HasNoTrailingPaddingOrUnknownFlags(t *testing.T){
	var f m1Fields;f.Nonce[0]=1;f.CookiePresent=true;raw:=buildM1(f);raw[8+117]=1
	if _,err:=parseM1(raw);!errors.Is(err,ErrMalformed){t.Fatal("nonzero cookie padding accepted")}
	raw=buildM1(f);raw[8+100]=2
	if _,err:=parseM1(raw);!errors.Is(err,ErrMalformed){t.Fatal("unknown cookie-present flag accepted")}
}

func TestM2M3LengthsAreFrozen(t *testing.T){
	if len(frame(TypeM2,make([]byte,M2BodySize)))!=252||len(frame(TypeM3,make([]byte,M3BodySize)))!=186||len(frame(TypeM4,make([]byte,M4BodySize)))!=72{t.Fatal("M2/M3/M4 frozen sizes changed")}
}

func TestM1LimiterExpiresIdlePrefixEntries(t *testing.T) {
	now:=time.Unix(1800000000,0)
	limiter,err:=NewM1Limiter(LimitConfig{GlobalRate:100,GlobalBurst:10,PerInterfaceRate:100,PerInterfaceBurst:10,PerPrefixRate:100,PerPrefixBurst:10,MaxTrackedPrefixes:1,PrefixIdleTTL:10*time.Second,Interfaces:[]string{"eth0"}})
	if err!=nil{t.Fatal(err)}
	if !limiter.Allow(now,netip.MustParseAddr("2001:db8:1::1"),"eth0"){t.Fatal("first prefix should be allowed")}
	if !limiter.Allow(now.Add(11*time.Second),netip.MustParseAddr("2001:db8:2::1"),"eth0"){t.Fatal("idle prefix slot should be reclaimed")}
}
