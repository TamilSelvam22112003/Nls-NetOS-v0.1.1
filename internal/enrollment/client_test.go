package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"os"
	"encoding/pem"
	"path/filepath"
	"testing"
)

func TestGenerateKeyAndCSR(t *testing.T) {
	dir:=t.TempDir()
	keyPath:=filepath.Join(dir,"router-key.pem")
	csrPath:=filepath.Join(dir,"router.csr.pem")
	hash,err:=GenerateKeyAndCSR("router-test",keyPath,csrPath);if err!=nil{t.Fatal(err)}
	if len(hash)!=64{t.Fatalf("public key hash length=%d",len(hash))}
	keyInfo,err:=os.Stat(keyPath);if err!=nil{t.Fatal(err)}
	if keyInfo.Mode().Perm()!=0600{t.Fatalf("key mode=%o",keyInfo.Mode().Perm())}
	keyPEM,err:=os.ReadFile(keyPath);if err!=nil{t.Fatal(err)}
	block,_:=pem.Decode(keyPEM);if block==nil{t.Fatal("missing key PEM")}
	anyKey,err:=x509.ParsePKCS8PrivateKey(block.Bytes);if err!=nil{t.Fatal(err)}
	priv,ok:=anyKey.(ed25519.PrivateKey);if !ok{t.Fatal("key is not Ed25519")}
	csrPEM,err:=os.ReadFile(csrPath);if err!=nil{t.Fatal(err)}
	csrBlock,_:=pem.Decode(csrPEM);if csrBlock==nil{t.Fatal("missing CSR PEM")}
	csr,err:=x509.ParseCertificateRequest(csrBlock.Bytes);if err!=nil{t.Fatal(err)}
	if err=csr.CheckSignature();err!=nil{t.Fatal(err)}
	if csr.Subject.CommonName!="router-test"{t.Fatalf("CN=%q",csr.Subject.CommonName)}
	if string(csr.PublicKey.(ed25519.PublicKey))!=string(priv.Public().(ed25519.PublicKey)){t.Fatal("CSR key does not match private key")}
}

func TestEnrollmentRejectsInvalidConfigurationBeforeDial(t *testing.T) {
	err:=Enroll(EnrollOptions{})
	if err==nil{t.Fatal("expected missing configuration error")}
}

func TestKeyGenerationUsesUniqueKeys(t *testing.T) {
	a,err:=GenerateKeyAndCSR("router-a",filepath.Join(t.TempDir(),"a.key"),filepath.Join(t.TempDir(),"a.csr"));if err!=nil{t.Fatal(err)}
	b,err:=GenerateKeyAndCSR("router-b",filepath.Join(t.TempDir(),"b.key"),filepath.Join(t.TempDir(),"b.csr"));if err!=nil{t.Fatal(err)}
	if a==b{t.Fatal("independent router keys unexpectedly match")}
	_,_,err=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
}
