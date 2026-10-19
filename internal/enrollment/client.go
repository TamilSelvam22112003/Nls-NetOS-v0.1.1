// Package enrollment implements the NLS Router-CA enrollment client.
package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
		"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	tlvEnrollmentRequest uint16 = 0x0010
	tlvEnrollmentResponse uint16 = 0x0011
	maxCSR = 4096
)

type EnrollOptions struct {
	Address string
	ServerName string
	RootCertificatePath string
	RootFingerprint string
	Name string
	Token string
	PrivateKeyPath string
	CSRPath string
	CertificateOut string
}

func GenerateKeyAndCSR(name,keyPath,csrPath string)(string,error) {
	if strings.TrimSpace(name)==""||len(name)>128||strings.ContainsRune(name,0){return "",errors.New("router name must be 1..128 bytes")}
	pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{return "",err}
	csrDER,err:=x509.CreateCertificateRequest(rand.Reader,&x509.CertificateRequest{Subject:pkixName(name)},priv);if err!=nil{return "",err}
	keyDER,err:=x509.MarshalPKCS8PrivateKey(priv);if err!=nil{return "",err}
	keyPEM:=pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:keyDER})
	csrPEM:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE REQUEST",Bytes:csrDER})
	if err=writeAtomic(keyPath,keyPEM,0600);err!=nil{return "",err}
	if err=writeAtomic(csrPath,csrPEM,0600);err!=nil{return "",err}
	sum:=sha256.Sum256(pub)
	return hex.EncodeToString(sum[:]),nil
}

func Enroll(o EnrollOptions) error {
	if o.Address==""||o.ServerName==""||o.RootCertificatePath==""||o.RootFingerprint==""||o.Name==""||o.Token==""||o.PrivateKeyPath==""||o.CSRPath==""||o.CertificateOut=="" {
		return errors.New("address, TLS name, CA certificate/fingerprint, name, token, key, CSR, and certificate output are required")
	}
	rootPEM,err:=os.ReadFile(o.RootCertificatePath);if err!=nil{return err}
	rootBlock,_:=pem.Decode(rootPEM);if rootBlock==nil||rootBlock.Type!="CERTIFICATE"{return errors.New("invalid CA root certificate PEM")}
	root,err:=x509.ParseCertificate(rootBlock.Bytes);if err!=nil{return err}
	expected,err:=hex.DecodeString(strings.TrimSpace(o.RootFingerprint));if err!=nil||len(expected)!=sha256.Size{return errors.New("CA fingerprint must be 64 hexadecimal characters")}
	actual:=sha256.Sum256(root.Raw)
	if !bytes.Equal(expected,actual[:]){return errors.New("CA root fingerprint pin mismatch")}
	roots:=x509.NewCertPool();roots.AddCert(root)
	tlsConfig:=&tls.Config{RootCAs:roots,ServerName:o.ServerName,MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13}
	dialer:=net.Dialer{Timeout:10*time.Second}
	conn,err:=tls.DialWithDialer(&dialer,"tcp",o.Address,tlsConfig);if err!=nil{return fmt.Errorf("TLS enrollment connection: %w",err)}
	defer conn.Close()
	if err=conn.SetDeadline(time.Now().Add(15*time.Second));err!=nil{return err}
	csrPEM,err:=os.ReadFile(o.CSRPath);if err!=nil{return err}
	csrBlock,_:=pem.Decode(csrPEM);if csrBlock==nil||csrBlock.Type!="CERTIFICATE REQUEST"{return errors.New("invalid CSR PEM")}
	if len(csrBlock.Bytes)>maxCSR{return errors.New("CSR exceeds 4096-byte protocol limit")}
	csr,err:=x509.ParseCertificateRequest(csrBlock.Bytes);if err!=nil{return err}
	if err=csr.CheckSignature();err!=nil{return fmt.Errorf("CSR proof of possession invalid: %w",err)}
	if csr.Subject.CommonName!=o.Name{return errors.New("CSR common name does not match enrollment name")}
	keyPEM,err:=os.ReadFile(o.PrivateKeyPath);if err!=nil{return err}
	keyBlock,_:=pem.Decode(keyPEM);if keyBlock==nil||keyBlock.Type!="PRIVATE KEY"{return errors.New("invalid router private key PEM")}
	keyAny,err:=x509.ParsePKCS8PrivateKey(keyBlock.Bytes);if err!=nil{return err}
	priv,ok:=keyAny.(ed25519.PrivateKey);if !ok{return errors.New("router private key must be Ed25519")}
	pub:=priv.Public().(ed25519.PublicKey)
	csrPub,ok:=csr.PublicKey.(ed25519.PublicKey)
	if !ok||!bytes.Equal(pub,csrPub){return errors.New("CSR public key does not match private key")}
	token:=[]byte(o.Token)
	if len(token)<1||len(token)>512{return errors.New("enrollment token length outside protocol bounds")}
	nameBytes:=[]byte(o.Name)
	if len(nameBytes)<1||len(nameBytes)>128{return errors.New("router name length outside protocol bounds")}
	value:=make([]byte,6)
	value[0],value[1]=1,byte(len(nameBytes))
	binary.BigEndian.PutUint16(value[2:4],uint16(len(token)))
	binary.BigEndian.PutUint16(value[4:6],uint16(len(csrBlock.Bytes)))
	value=append(value,nameBytes...);value=append(value,token...);value=append(value,csrBlock.Bytes...)
	if err=writeTLV(conn,tlvEnrollmentRequest,value);err!=nil{return err}
	typ,response,err:=readTLV(conn,6+8+8192+8);if err!=nil{return err}
	if typ!=tlvEnrollmentResponse||len(response)<16{return errors.New("malformed enrollment response")}
	if response[0]!=1{return errors.New("unsupported enrollment response schema")}
	status:=response[1]
	code:=binary.BigEndian.Uint16(response[2:4])
	certLen:=binary.BigEndian.Uint32(response[4:8])
	if uint64(certLen)+16!=uint64(len(response)) {return errors.New("enrollment response length mismatch")}
	if status!=1 {
		if status!=2||certLen!=0{return errors.New("invalid enrollment rejection response")}
		return fmt.Errorf("CA rejected enrollment with protocol error 0x%04x",code)
	}
	if code!=0||certLen==0||certLen>8192{return errors.New("invalid successful enrollment response")}
	certDER:=response[8:8+int(certLen)]
	serial:=binary.BigEndian.Uint64(response[8+int(certLen):])
	cert,err:=x509.ParseCertificate(certDER);if err!=nil{return err}
	if cert.SerialNumber.Uint64()!=serial{return errors.New("certificate serial mismatch")}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo,csr.RawSubjectPublicKeyInfo){return errors.New("issued certificate key does not match CSR")}
	if _,err=cert.Verify(x509.VerifyOptions{Roots:roots,KeyUsages:[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}});err!=nil{return fmt.Errorf("issued certificate verification failed: %w",err)}
	certOut:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:certDER})
	if err=writeAtomic(o.CertificateOut,certOut,0600);err!=nil{return err}
	fmt.Printf("enrollment successful; certificate serial %d saved to %s\n",serial,o.CertificateOut)
	return nil
}

func readTLV(r io.Reader,max int)(uint16,[]byte,error) {
	var h [6]byte;if _,err:=io.ReadFull(r,h[:]);err!=nil{return 0,nil,err}
	n:=binary.BigEndian.Uint32(h[2:]);if uint64(n)>uint64(max){return 0,nil,errors.New("TLV exceeds limit")}
	v:=make([]byte,int(n));if _,err:=io.ReadFull(r,v);err!=nil{return 0,nil,err}
	return binary.BigEndian.Uint16(h[:2]),v,nil
}
func writeTLV(w io.Writer,typ uint16,value []byte)error {
	h:=make([]byte,6);binary.BigEndian.PutUint16(h[:2],typ);binary.BigEndian.PutUint32(h[2:],uint32(len(value)))
	if err:=writeFull(w,h);err!=nil{return err};return writeFull(w,value)
}
func writeFull(w io.Writer,b []byte)error {for len(b)>0{n,err:=w.Write(b);if err!=nil{return err};if n==0{return io.ErrShortWrite};b=b[n:]};return nil}
func writeAtomic(path string,data []byte,mode os.FileMode)error {
	if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return err}
	f,err:=os.CreateTemp(filepath.Dir(path),".nls-router-*");if err!=nil{return err}
	tmp:=f.Name();defer os.Remove(tmp)
	if err=f.Chmod(mode);err!=nil{_ = f.Close();return err}
	if err=writeFull(f,data);err!=nil{_ = f.Close();return err}
	if err=f.Sync();err!=nil{_ = f.Close();return err}
	if err=f.Close();err!=nil{return err}
	if err=os.Rename(tmp,path);err!=nil{return err}
	d,err:=os.Open(filepath.Dir(path));if err==nil{_ = d.Sync();_ = d.Close()}
	return nil
}
func pkixName(name string) pkix.Name {return pkix.Name{CommonName:name,Organization:[]string{"NLS Router"}}}
