// Package directory's TLSClient performs mandatory online RDR lookup over mTLS.
package directory

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const (
	tlvDirectoryLookup uint16 = 0x0040
	tlvDirectoryResponse uint16 = 0x0041
)

type TLSClientOptions struct {
	Address string
	ServerName string
	RootCertificatePath string
	RootFingerprint string
	CertificatePath string
	PrivateKeyPath string
	Timeout time.Duration
}

type TLSClient struct { options TLSClientOptions; tlsConfig *tls.Config; timeout time.Duration; caPublicKey ed25519.PublicKey }

func NewTLSClient(o TLSClientOptions) (*TLSClient,error) {
	if o.Address==""||o.ServerName==""||o.RootCertificatePath==""||o.RootFingerprint==""||o.CertificatePath==""||o.PrivateKeyPath=="" {
		return nil,errors.New("address, TLS name, pinned root, router certificate and private key are required")
	}
	rootPEM,err:=os.ReadFile(o.RootCertificatePath);if err!=nil{return nil,err}
	block,_:=pem.Decode(rootPEM)
	if block==nil||block.Type!="CERTIFICATE"{return nil,errors.New("invalid Router-CA root certificate PEM")}
	root,err:=x509.ParseCertificate(block.Bytes);if err!=nil{return nil,err}
	pin,err:=hex.DecodeString(strings.TrimSpace(o.RootFingerprint))
	if err!=nil||len(pin)!=sha256.Size{return nil,errors.New("root fingerprint must be 64 hexadecimal characters")}
	actual:=sha256.Sum256(root.Raw)
	if !bytes.Equal(pin,actual[:]){return nil,errors.New("Router-CA root fingerprint pin mismatch")}
	caPub,ok:=root.PublicKey.(ed25519.PublicKey);if !ok{return nil,errors.New("Router-CA root key must be Ed25519")}
	cert,err:=tls.LoadX509KeyPair(o.CertificatePath,o.PrivateKeyPath);if err!=nil{return nil,err}
	roots:=x509.NewCertPool();roots.AddCert(root)
	timeout:=o.Timeout;if timeout<=0{timeout=10*time.Second}
	return &TLSClient{options:o,timeout:timeout,caPublicKey:append(ed25519.PublicKey(nil),caPub...),tlsConfig:&tls.Config{RootCAs:roots,ServerName:o.ServerName,Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13}},nil
}

func (c *TLSClient) Lookup(ctx context.Context, routerID [16]byte)(uint16,[]byte,error) {
	dialer:=net.Dialer{Timeout:c.timeout}
	rawConn,err:=dialer.DialContext(ctx,"tcp",c.options.Address)
	if err!=nil{return LookupUnavailable,nil,fmt.Errorf("%w: %v",ErrCAUnavailable,err)}
	defer rawConn.Close()
	conn:=tls.Client(rawConn,c.tlsConfig.Clone())
	handshakeCtx,cancel:=context.WithTimeout(ctx,c.timeout);defer cancel()
	if err=conn.HandshakeContext(handshakeCtx);err!=nil{return LookupUnavailable,nil,fmt.Errorf("%w: TLS handshake: %v",ErrCAUnavailable,err)}
	deadline:=time.Now().Add(c.timeout)
	if d,ok:=ctx.Deadline();ok&&d.Before(deadline){deadline=d}
	_ = conn.SetDeadline(deadline)
	var random [8]byte
	if _,err=rand.Read(random[:]);err!=nil{return LookupUnavailable,nil,err}
	requestID:=binary.BigEndian.Uint64(random[:]);if requestID==0{requestID=1}
	value:=make([]byte,24);binary.BigEndian.PutUint64(value[:8],requestID);copy(value[8:],routerID[:])
	if err=writeTLV(conn,tlvDirectoryLookup,value);err!=nil{return LookupUnavailable,nil,fmt.Errorf("%w: send lookup: %v",ErrCAUnavailable,err)}
	typ,response,err:=readTLV(conn,12+RDRSize)
	if err!=nil{return LookupUnavailable,nil,fmt.Errorf("%w: read lookup response: %v",ErrCAUnavailable,err)}
	if typ!=tlvDirectoryResponse||len(response)<12{return LookupUnavailable,nil,errors.New("malformed directory response")}
	if binary.BigEndian.Uint64(response[:8])!=requestID{return LookupUnavailable,nil,errors.New("directory response request ID mismatch")}
	status:=binary.BigEndian.Uint16(response[8:10]);n:=int(binary.BigEndian.Uint16(response[10:12]))
	if n!=len(response)-12{return LookupUnavailable,nil,errors.New("directory response RDR length mismatch")}
	if status!=LookupFound&&n!=0{return LookupUnavailable,nil,errors.New("non-found directory response contains an RDR")}
	if status==LookupFound&&n!=RDRSize{return LookupUnavailable,nil,errors.New("found directory response has invalid RDR size")}
	return status,append([]byte(nil),response[12:]...),nil
}

func writeTLV(w io.Writer,typ uint16,value []byte)error { var h [6]byte;binary.BigEndian.PutUint16(h[:2],typ);binary.BigEndian.PutUint32(h[2:],uint32(len(value)));if err:=writeFull(w,h[:]);err!=nil{return err};return writeFull(w,value) }
func readTLV(r io.Reader,max int)(uint16,[]byte,error) { var h [6]byte;if _,err:=io.ReadFull(r,h[:]);err!=nil{return 0,nil,err};n:=binary.BigEndian.Uint32(h[2:]);if uint64(n)>uint64(max){return 0,nil,errors.New("TLV exceeds limit")};value:=make([]byte,int(n));if _,err:=io.ReadFull(r,value);err!=nil{return 0,nil,err};return binary.BigEndian.Uint16(h[:2]),value,nil }
func writeFull(w io.Writer,b []byte)error {for len(b)>0{n,err:=w.Write(b);if err!=nil{return err};if n==0{return io.ErrShortWrite};b=b[n:]};return nil}

// CAPublicKey returns the pinned Router-CA Ed25519 key used to verify RDR signatures.
func (c *TLSClient) CAPublicKey() ed25519.PublicKey { return append(ed25519.PublicKey(nil), c.caPublicKey...) }
