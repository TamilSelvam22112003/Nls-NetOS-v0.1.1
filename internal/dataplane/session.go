// Package dataplane implements NLS v1 authenticated data transport.
package dataplane

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	Version byte = 1
	TypeData byte = 0x10
	TypeRekeyInit byte = 0x11
	TypeRekeyAck byte = 0x12
	CommonHeaderSize = 8
	DataHeaderSize = 32
	GCMTagSize = 16
	MaxUDPPayload = 1452
	OuterOverhead = 104
	DefaultPathMTU = 1500
	DefaultInnerMTU = DefaultPathMTU - OuterOverhead
	ReplayWindowSize uint64 = 1024
	RekeyPacketLimit uint64 = 1 << 32
	HardStopPacketLimit uint64 = (1 << 32) + (1 << 20)
	DefaultRekeyInterval = time.Hour
)
var (
	ErrMalformed = errors.New("malformed NLS data datagram")
	ErrNoSession = errors.New("NLS session not found")
	ErrBadTag = errors.New("NLS AEAD authentication failed")
	ErrReplay = errors.New("NLS replay rejected")
	ErrOversize = errors.New("NLS packet exceeds negotiated MTU")
	ErrBadInnerPacket = errors.New("invalid inner IP packet")
	ErrRekeyRequired = errors.New("NLS session requires rekey")
	ErrHardStop = errors.New("NLS session hard limit reached")
	ErrBadRekey = errors.New("NLS rekey authentication failed")
)

type Config struct {
	SessionID uint16
	NonceID [16]byte
	SendKey [32]byte
	ReceiveKey [32]byte
	SendSalt [4]byte
	ReceiveSalt [4]byte
	InnerMTU int
	RekeyAfterPackets uint64
	HardStopPackets uint64
	RekeyAfter time.Duration
	Now func() time.Time
	LocalPrivate ed25519.PrivateKey
	PeerPublic ed25519.PublicKey
	LocalIsInitiator bool
	TranscriptHash [32]byte
}
type Session struct {
	mu sync.Mutex
	id uint16
	nonceID [16]byte
	sendKey, receiveKey [32]byte
	sendSalt, receiveSalt [4]byte
	innerMTU int
	sendSeq, recvHighest uint64
	received map[uint64]struct{}
	epoch uint32
	createdAt, lastRekey time.Time
	rekeyAfterPackets, hardStopPackets uint64
	rekeyAfter time.Duration
	now func() time.Time
	localPrivate ed25519.PrivateKey
	peerPublic ed25519.PublicKey
	localIsInitiator bool
	transcriptHash [32]byte
	pending *pendingRekey
}
type pendingRekey struct {
	epoch uint32
	private []byte
	public [32]byte
	transcript [32]byte
}
type Keys struct {
	I2R [32]byte
	R2I [32]byte
	SaltI2R [4]byte
	SaltR2I [4]byte
}
func NewSession(cfg Config) (*Session,error) {
	if cfg.SessionID==0 { return nil,errors.New("session ID must be nonzero") }
	if cfg.InnerMTU==0 { cfg.InnerMTU=DefaultInnerMTU }
	if cfg.InnerMTU<1280 || cfg.InnerMTU>DefaultInnerMTU { return nil,fmt.Errorf("inner MTU must be 1280..%d",DefaultInnerMTU) }
	if cfg.RekeyAfterPackets==0 { cfg.RekeyAfterPackets=RekeyPacketLimit }
	if cfg.HardStopPackets==0 { cfg.HardStopPackets=HardStopPacketLimit }
	if cfg.HardStopPackets<=cfg.RekeyAfterPackets { return nil,errors.New("hard stop must exceed rekey threshold") }
	if cfg.RekeyAfter<=0 { cfg.RekeyAfter=DefaultRekeyInterval }
	if cfg.Now==nil { cfg.Now=time.Now }
	if len(cfg.LocalPrivate)!=0 && len(cfg.LocalPrivate)!=ed25519.PrivateKeySize { return nil,errors.New("invalid local Ed25519 private key") }
	if len(cfg.PeerPublic)!=0 && len(cfg.PeerPublic)!=ed25519.PublicKeySize { return nil,errors.New("invalid peer Ed25519 public key") }
	now:=cfg.Now()
	return &Session{id:cfg.SessionID,nonceID:cfg.NonceID,sendKey:cfg.SendKey,receiveKey:cfg.ReceiveKey,sendSalt:cfg.SendSalt,receiveSalt:cfg.ReceiveSalt,innerMTU:cfg.InnerMTU,received:make(map[uint64]struct{}),createdAt:now,lastRekey:now,rekeyAfterPackets:cfg.RekeyAfterPackets,hardStopPackets:cfg.HardStopPackets,rekeyAfter:cfg.RekeyAfter,now:cfg.Now,localPrivate:append(ed25519.PrivateKey(nil),cfg.LocalPrivate...),peerPublic:append(ed25519.PublicKey(nil),cfg.PeerPublic...),localIsInitiator:cfg.LocalIsInitiator,transcriptHash:cfg.TranscriptHash},nil
}
func (s *Session) ID() uint16 { return s.id }
func (s *Session) PeerIdentityKey() ed25519.PublicKey { return append(ed25519.PublicKey(nil),s.peerPublic...) }
func (s *Session) NeedsRekey() bool {
	s.mu.Lock();defer s.mu.Unlock()
	return s.sendSeq>=s.rekeyAfterPackets || s.now().Sub(s.lastRekey)>=s.rekeyAfter
}
func (s *Session) checkSendLimitLocked() error {
	if s.sendSeq+1>=s.hardStopPackets { return ErrHardStop }
	if s.sendSeq>=s.rekeyAfterPackets || s.now().Sub(s.lastRekey)>=s.rekeyAfter { return ErrRekeyRequired }
	return nil
}
func nonce(salt [4]byte,seq uint64) []byte { n:=make([]byte,12);copy(n[:4],salt[:]);binary.BigEndian.PutUint64(n[4:],seq);return n }
func commonHeader(typ byte,bodyLen int) []byte {
	b:=make([]byte,CommonHeaderSize);b[0]=Version;b[1]=typ;binary.BigEndian.PutUint16(b[4:6],uint16(bodyLen));return b
}
func dataHeader(id uint16,nonceID [16]byte,seq uint64) []byte {
	b:=make([]byte,DataHeaderSize);b[0]=Version;binary.BigEndian.PutUint16(b[2:4],id);copy(b[4:20],nonceID[:]);binary.BigEndian.PutUint64(b[20:28],seq);return b
}
func parseFrame(raw []byte,typ byte)([]byte,[]byte,error) {
	if len(raw)<CommonHeaderSize+DataHeaderSize+GCMTagSize || len(raw)>MaxUDPPayload || raw[0]!=Version || raw[1]!=typ || binary.BigEndian.Uint16(raw[2:4])!=0 || binary.BigEndian.Uint16(raw[6:8])!=0 { return nil,nil,ErrMalformed }
	n:=int(binary.BigEndian.Uint16(raw[4:6]))
	if n!=len(raw)-CommonHeaderSize { return nil,nil,ErrMalformed }
	h:=raw[CommonHeaderSize:CommonHeaderSize+DataHeaderSize]
	if h[0]!=Version||h[1]!=0||binary.BigEndian.Uint32(h[28:32])!=0 { return nil,nil,ErrMalformed }
	return h,raw[CommonHeaderSize+DataHeaderSize:],nil
}
func (s *Session) Encrypt(inner []byte) ([]byte,error) {
	if len(inner)>s.innerMTU { return nil,ErrOversize }
	if err:=validateInnerPacket(inner);err!=nil{return nil,err}
	s.mu.Lock();defer s.mu.Unlock()
	if err:=s.checkSendLimitLocked();err!=nil{return nil,err}
	seq:=s.sendSeq+1
	block,err:=aes.NewCipher(s.sendKey[:]);if err!=nil{return nil,err};gcm,err:=cipher.NewGCM(block);if err!=nil{return nil,err}
	h:=dataHeader(s.id,s.nonceID,seq);header:=commonHeader(TypeData,len(h)+len(inner)+GCMTagSize);aad:=append(append([]byte{},header...),h...)
	sealed:=gcm.Seal(nil,nonce(s.sendSalt,seq),inner,aad)
	out:=append(append(header,h...),sealed...)
	if len(out)>MaxUDPPayload{return nil,ErrOversize}
	s.sendSeq=seq
	return out,nil
}
func (s *Session) Decrypt(datagram []byte) ([]byte,error) {
	h,sealed,err:=parseFrame(datagram,TypeData);if err!=nil{return nil,err}
	id:=binary.BigEndian.Uint16(h[2:4]);seq:=binary.BigEndian.Uint64(h[20:28])
	if id==0||id!=s.id||subtle.ConstantTimeCompare(h[4:20],s.nonceID[:])!=1||seq==0{return nil,ErrNoSession}
	s.mu.Lock();defer s.mu.Unlock()
	if seq<=s.recvHighest && s.recvHighest-seq>=ReplayWindowSize { return nil,ErrReplay }
	if _,ok:=s.received[seq];ok{return nil,ErrReplay}
	block,err:=aes.NewCipher(s.receiveKey[:]);if err!=nil{return nil,err};gcm,err:=cipher.NewGCM(block);if err!=nil{return nil,err}
	header:=datagram[:CommonHeaderSize];aad:=append(append([]byte{},header...),h...)
	plain,err:=gcm.Open(nil,nonce(s.receiveSalt,seq),sealed,aad);if err!=nil{return nil,ErrBadTag}
	if err=validateInnerPacket(plain);err!=nil{return nil,err}
	if seq>s.recvHighest{s.recvHighest=seq}
	s.received[seq]=struct{}{}
	floor:=uint64(0);if s.recvHighest>=ReplayWindowSize{floor=s.recvHighest-ReplayWindowSize+1}
	for old:=range s.received{if old<floor{delete(s.received,old)}}
	return plain,nil
}
func validateInnerPacket(p []byte) error {
	if len(p)<1{return ErrBadInnerPacket}
	switch p[0]>>4 {
	case 4:
		if len(p)<20||int(binary.BigEndian.Uint16(p[2:4]))!=len(p){return ErrBadInnerPacket}
		ihl:=int(p[0]&0x0f)*4;if ihl<20||ihl>len(p){return ErrBadInnerPacket}
	case 6:
		if len(p)<40||int(binary.BigEndian.Uint16(p[4:6]))+40!=len(p){return ErrBadInnerPacket}
	default:return ErrBadInnerPacket
	}
	return nil
}

// InstallRekey atomically switches keys after an authenticated rekey exchange.
// The caller must authenticate the REKEY_ACK before invoking this method.
func (s *Session) InstallRekey(epoch uint32,keys Keys,transcript [32]byte) error {
	s.mu.Lock();defer s.mu.Unlock()
	if epoch!=s.epoch+1{return ErrBadRekey}
	if s.pending!=nil && s.pending.epoch!=epoch{return ErrBadRekey}
	if s.localIsInitiator{s.sendKey=keys.I2R;s.receiveKey=keys.R2I;s.sendSalt=keys.SaltI2R;s.receiveSalt=keys.SaltR2I}else{s.sendKey=keys.R2I;s.receiveKey=keys.I2R;s.sendSalt=keys.SaltR2I;s.receiveSalt=keys.SaltI2R}
	s.epoch=epoch;s.transcriptHash=transcript;s.sendSeq=0;s.recvHighest=0;s.received=make(map[uint64]struct{});s.lastRekey=s.now();s.pending=nil
	return nil
}

// DeriveRekeyKeys implements the frozen replacement-key HKDF labels.
func DeriveRekeyKeys(shared []byte,oldTranscript,rekeyTranscript [32]byte)(Keys,error) {
	var out Keys
	if len(shared)!=32 { return out,ErrBadRekey }
	saltHash:=sha256.Sum256(append(append([]byte{},oldTranscript[:]...),rekeyTranscript[:]...))
	derive:=func(label string,n int)([]byte,error){r:=hkdf.New(sha256.New,shared,saltHash[:],[]byte(label));b:=make([]byte,n);_,err:=ioReadFull(r,b);return b,err}
	for _,x:=range []struct{label string;dst []byte}{{"NLS-v1 rekey i2r",out.I2R[:]},{"NLS-v1 rekey r2i",out.R2I[:]},{"NLS-v1 nonce i2r",out.SaltI2R[:]},{"NLS-v1 nonce r2i",out.SaltR2I[:]}}{b,e:=derive(x.label,len(x.dst));if e!=nil{return Keys{},e};copy(x.dst,b)}
	return out,nil
}
func ioReadFull(r interface{Read([]byte)(int,error)},p []byte) error { for len(p)>0 { n,e:=r.Read(p);if n>0{p=p[n:]};if e!=nil{return e};if n==0{return errors.New("HKDF returned no data")} };return nil }

// RekeySignatureInput is the context-separated signed payload required by PROTOCOL.md.
func RekeySignatureInput(transcript [32]byte,epoch uint32,ephemeral [32]byte) []byte {
	b:=make([]byte,0,len("NLS-v1-REKEY\x00")+32+4+32);b=append(b,[]byte("NLS-v1-REKEY\x00")...);b=append(b,transcript[:]...);var e [4]byte;binary.BigEndian.PutUint32(e[:],epoch);b=append(b,e[:]...);b=append(b,ephemeral[:]...);return b
}
func VerifyRekeySignature(pub ed25519.PublicKey,transcript [32]byte,epoch uint32,ephemeral [32]byte,sig []byte) bool {
	if len(pub)!=ed25519.PublicKeySize||len(sig)!=ed25519.SignatureSize{return false}
	return ed25519.Verify(pub,RekeySignatureInput(transcript,epoch,ephemeral),sig)
}
func constantTimeEqual(a,b []byte) bool { return hmac.Equal(a,b) }
var _ = constantTimeEqual
var _ netip.Addr
