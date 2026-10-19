package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/TamilSelvam22112003/Nls-NetOS-v0.1.1/internal/control"
	"github.com/TamilSelvam22112003/Nls-NetOS-v0.1.1/internal/directory"
	"github.com/TamilSelvam22112003/Nls-NetOS-v0.1.1/internal/enrollment"
	nlsHandshake "github.com/TamilSelvam22112003/Nls-NetOS-v0.1.1/internal/handshake"
)

func main() {
	if err:=run(os.Args[1:]);err!=nil{fmt.Fprintln(os.Stderr,"error:",err);os.Exit(1)}
}

func run(args []string)error {
	if len(args)==0{usage();return fmt.Errorf("command required")}
	switch args[0] {
	case "help","-h","--help":usage();return nil
	case "keygen":return keygen(args[1:])
	case "enroll":return enroll(args[1:])
	case "control":return controlClient(args[1:])
	case "handshake":return handshakeClient(args[1:])
	case "handshake-listen":return handshakeListen(args[1:])
	default:usage();return fmt.Errorf("unknown command %q",args[0])
	}
}

func keygen(args []string)error {
	fs:=flag.NewFlagSet("keygen",flag.ContinueOnError);fs.SetOutput(os.Stderr)
	name:=fs.String("name","","router identity name")
	key:=fs.String("key-out","router-key.pem","private key output path")
	csr:=fs.String("csr-out","router.csr.pem","CSR output path")
	if err:=fs.Parse(args);err!=nil{return err};if fs.NArg()!=0{return fmt.Errorf("unexpected positional arguments")}
	hash,err:=enrollment.GenerateKeyAndCSR(*name,*key,*csr);if err!=nil{return err}
	fmt.Println("public-key-sha256="+hash)
	fmt.Println("private key:",*key)
	fmt.Println("CSR:",*csr)
	return nil
}

func enroll(args []string)error {
	fs:=flag.NewFlagSet("enroll",flag.ContinueOnError);fs.SetOutput(os.Stderr)
	address:=fs.String("address","","CA host:port")
	serverName:=fs.String("tls-name","","CA TLS DNS name")
	caCert:=fs.String("ca-cert","ca-cert.pem","pinned CA root certificate PEM")
	fingerprint:=fs.String("ca-fingerprint","","expected SHA-256 fingerprint of CA certificate DER")
	name:=fs.String("name","","router name")
	key:=fs.String("key","router-key.pem","router private key PEM")
	csr:=fs.String("csr","router.csr.pem","router CSR PEM")
	certOut:=fs.String("cert-out","router-cert.pem","issued router certificate output")
	if err:=fs.Parse(args);err!=nil{return err};if fs.NArg()!=0{return fmt.Errorf("unexpected positional arguments")}
	token:=os.Getenv("NLS_ENROLLMENT_TOKEN")
	if strings.TrimSpace(token)==""{return fmt.Errorf("set NLS_ENROLLMENT_TOKEN in the environment; token is never accepted as a command-line argument")}
	return enrollment.Enroll(enrollment.EnrollOptions{Address:*address,ServerName:*serverName,RootCertificatePath:*caCert,RootFingerprint:*fingerprint,Name:*name,Token:token,PrivateKeyPath:*key,CSRPath:*csr,CertificateOut:*certOut})
}

func controlClient(args []string)error {
	fs:=flag.NewFlagSet("control",flag.ContinueOnError);fs.SetOutput(os.Stderr)
	address:=fs.String("address","","CA host:port")
	serverName:=fs.String("tls-name","","CA TLS DNS name")
	caCert:=fs.String("ca-cert","ca-cert.pem","Router-CA root certificate PEM")
	fingerprint:=fs.String("ca-fingerprint","","expected SHA-256 fingerprint of CA certificate DER")
	cert:=fs.String("cert","router-cert.pem","issued router certificate PEM")
	key:=fs.String("key","router-key.pem","router private key PEM")
	stateDir:=fs.String("state-dir","/var/lib/nls-router","persistent policy/revocation state directory")
	interval:=fs.Duration("interval",5*time.Second,"heartbeat/sync interval")
	controlLossTimeout:=fs.Duration("control-loss-timeout",control.DefaultControlLossTimeout,"drop existing sessions after this much control loss (default 5m)")
	if err:=fs.Parse(args);err!=nil{return err};if fs.NArg()!=0{return fmt.Errorf("unexpected positional arguments")}
	ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer stop()
	return control.Run(ctx,control.Options{Address:*address,ServerName:*serverName,RootCertificatePath:*caCert,RootFingerprint:*fingerprint,CertificatePath:*cert,PrivateKeyPath:*key,StateDir:*stateDir,Interval:*interval,ControlLossTimeout:*controlLossTimeout})
}


type handshakeFiles struct {
	record directory.Record
	private ed25519.PrivateKey
	caPublic ed25519.PublicKey
	cache *directory.Cache
}

func loadHandshakeFiles(localRDR,caCert,caFingerprint,routerCert,routerKey,controlAddress,tlsName string)(handshakeFiles,error){
	var out handshakeFiles
	if localRDR==""||caCert==""||caFingerprint==""||routerCert==""||routerKey==""||controlAddress==""||tlsName==""{return out,fmt.Errorf("local RDR, CA certificate/fingerprint, router certificate/key, control address and TLS name are required")}
	rootPEM,err:=os.ReadFile(caCert);if err!=nil{return out,err}
	block,_:=pem.Decode(rootPEM);if block==nil||block.Type!="CERTIFICATE"{return out,fmt.Errorf("invalid Router-CA root certificate PEM")}
	root,err:=x509.ParseCertificate(block.Bytes);if err!=nil{return out,err}
	caPub,ok:=root.PublicKey.(ed25519.PublicKey);if !ok{return out,fmt.Errorf("Router-CA root public key must be Ed25519")}
	raw,err:=os.ReadFile(localRDR);if err!=nil{return out,err}
	record,err:=directory.VerifyRDR(raw,caPub,time.Now());if err!=nil{return out,fmt.Errorf("local RDR: %w",err)}
	keyPEM,err:=os.ReadFile(routerKey);if err!=nil{return out,err}
	keyBlock,_:=pem.Decode(keyPEM);if keyBlock==nil||keyBlock.Type!="PRIVATE KEY"{return out,fmt.Errorf("invalid router private key PEM")}
	keyAny,err:=x509.ParsePKCS8PrivateKey(keyBlock.Bytes);if err!=nil{return out,err}
	private,ok:=keyAny.(ed25519.PrivateKey);if !ok{return out,fmt.Errorf("router private key must be Ed25519")}
	tlsClient,err:=directory.NewTLSClient(directory.TLSClientOptions{Address:controlAddress,ServerName:tlsName,RootCertificatePath:caCert,RootFingerprint:caFingerprint,CertificatePath:routerCert,PrivateKeyPath:routerKey,Timeout:10*time.Second});if err!=nil{return out,err}
	cache,err:=directory.NewCache(caPub,directory.DefaultCacheTTL,tlsClient.Lookup);if err!=nil{return out,err}
	return handshakeFiles{record:record,private:private,caPublic:caPub,cache:cache},nil
}

func handshakeClient(args []string)error{
	fs:=flag.NewFlagSet("handshake",flag.ContinueOnError);fs.SetOutput(os.Stderr)
	localRDR:=fs.String("local-rdr","","local signed RDR binary file (322 bytes)")
	controlAddress:=fs.String("control-address","","Router-CA control host:port")
	tlsName:=fs.String("tls-name","","Router-CA TLS DNS name")
	caCert:=fs.String("ca-cert","ca-cert.pem","pinned Router-CA root certificate PEM")
	fingerprint:=fs.String("ca-fingerprint","","SHA-256 root certificate fingerprint")
	cert:=fs.String("cert","router-cert.pem","issued router certificate for mTLS lookup")
	key:=fs.String("key","router-key.pem","router Ed25519 private key PEM")
	peerIDText:=fs.String("peer-id","","destination router ID as 32 hex characters")
	wanAddressText:=fs.String("wan-address","","local real WAN IPv6 address")
	wanPrefixText:=fs.String("wan-prefix","","routed WAN IPv6 prefix")
	iface:=fs.String("interface","","WAN interface used for temporary vIP")
	dadTimeout:=fs.Duration("dad-timeout",0,"explicit DAD timeout (ADR-0005 does not set a value)")
	dadPoll:=fs.Duration("dad-poll-interval",0,"explicit DAD polling interval")
	if err:=fs.Parse(args);err!=nil{return err};if fs.NArg()!=0{return fmt.Errorf("unexpected positional arguments")}
	peerBytes,err:=hex.DecodeString(*peerIDText);if err!=nil||len(peerBytes)!=16{return fmt.Errorf("peer-id must be exactly 32 hexadecimal characters")}
	var peerID [16]byte;copy(peerID[:],peerBytes)
	wanAddress,err:=netip.ParseAddr(*wanAddressText);if err!=nil{return fmt.Errorf("invalid --wan-address: %w",err)}
	wanPrefix,err:=netip.ParsePrefix(*wanPrefixText);if err!=nil{return fmt.Errorf("invalid --wan-prefix: %w",err)}
	files,err:=loadHandshakeFiles(*localRDR,*caCert,*fingerprint,*cert,*key,*controlAddress,*tlsName);if err!=nil{return err}
	ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer stop()
	peer,err:=files.cache.LookupForHandshake(ctx,peerID);if err!=nil{return fmt.Errorf("initial online peer lookup: %w",err)}
	vip:=nlsHandshake.LinuxVIPProvider{DADTimeout:*dadTimeout,PollInterval:*dadPoll}
	session,err:=nlsHandshake.Initiate(ctx,nlsHandshake.InitiatorConfig{LocalRecord:files.record,PrivateKey:files.private,CAPublicKey:files.caPublic,Directory:files.cache,VIP:vip,WANAddress:wanAddress,WANPrefix:wanPrefix,Interface:*iface,Timeout:10*time.Second},peerID,peer.Endpoint)
	if err!=nil{return err}
	fmt.Printf("M1-M4 authenticated; peer=%x; session keys derived; local WAN endpoint=%s; peer WAN endpoint=%s\n",session.PeerRouterID,session.LocalEndpoint,session.PeerEndpoint)
	fmt.Println("Note: the data-plane session manager is not yet implemented; derived keys are not installed for traffic.")
	return nil
}

func handshakeListen(args []string)error{
	fs:=flag.NewFlagSet("handshake-listen",flag.ContinueOnError);fs.SetOutput(os.Stderr)
	localRDR:=fs.String("local-rdr","","local signed RDR binary file (322 bytes)")
	controlAddress:=fs.String("control-address","","Router-CA control host:port")
	tlsName:=fs.String("tls-name","","Router-CA TLS DNS name")
	caCert:=fs.String("ca-cert","ca-cert.pem","pinned Router-CA root certificate PEM")
	fingerprint:=fs.String("ca-fingerprint","","SHA-256 root certificate fingerprint")
	cert:=fs.String("cert","router-cert.pem","issued router certificate for mTLS lookup")
	key:=fs.String("key","router-key.pem","router Ed25519 private key PEM")
	ingress:=fs.String("ingress-interface","","ingress interface name used for per-interface M1 limiting")
	globalRate:=fs.Float64("global-rate",0,"required global M1 tokens per second")
	globalBurst:=fs.Float64("global-burst",0,"required global M1 burst")
	ifaceRate:=fs.Float64("interface-rate",0,"required per-interface M1 tokens per second")
	ifaceBurst:=fs.Float64("interface-burst",0,"required per-interface M1 burst")
	prefixRate:=fs.Float64("prefix-rate",0,"required per-source-/64 M1 tokens per second")
	prefixBurst:=fs.Float64("prefix-burst",0,"required per-source-/64 M1 burst")
	prefixIdleTTL:=fs.Duration("prefix-idle-ttl",0,"required idle lifetime before a tracked source-/64 slot can be reclaimed")
	maxPrefixes:=fs.Int("max-tracked-prefixes",0,"required maximum tracked source-/64 prefixes")
	maxPending:=fs.Int("max-pending",0,"required maximum global pending handshakes")
	maxPendingPrefix:=fs.Int("max-pending-per-prefix",0,"required maximum pending handshakes per source-/64")
	pendingTTL:=fs.Duration("pending-ttl",3*time.Second,"pending handshake lifetime (protocol M3 wait: 3s)")
	if err:=fs.Parse(args);err!=nil{return err};if fs.NArg()!=0{return fmt.Errorf("unexpected positional arguments")}
	if strings.TrimSpace(*ingress)==""{return fmt.Errorf("--ingress-interface is required")}
	files,err:=loadHandshakeFiles(*localRDR,*caCert,*fingerprint,*cert,*key,*controlAddress,*tlsName);if err!=nil{return err}
	limiter,err:=nlsHandshake.NewM1Limiter(nlsHandshake.LimitConfig{GlobalRate:*globalRate,GlobalBurst:*globalBurst,PerInterfaceRate:*ifaceRate,PerInterfaceBurst:*ifaceBurst,PerPrefixRate:*prefixRate,PerPrefixBurst:*prefixBurst,MaxTrackedPrefixes:*maxPrefixes,PrefixIdleTTL:*prefixIdleTTL,Interfaces:[]string{*ingress}});if err!=nil{return err}
	cookies,err:=nlsHandshake.NewCookieManager(time.Now);if err!=nil{return err}
	responder,err:=nlsHandshake.NewResponder(nlsHandshake.ResponderConfig{LocalRecord:files.record,PrivateKey:files.private,CAPublicKey:files.caPublic,Directory:files.cache,Cookies:cookies,Limiter:limiter,MaxPending:*maxPending,MaxPendingPerPrefix:*maxPendingPrefix,PendingTTL:*pendingTTL,OnEstablished:func(s nlsHandshake.Session){fmt.Printf("peer handshake authenticated: %x\n",s.PeerRouterID)}});if err!=nil{return err}
	conn,err:=net.ListenUDP("udp6",&net.UDPAddr{IP:net.IP(files.record.Endpoint.Addr().AsSlice()),Port:int(files.record.Endpoint.Port())});if err!=nil{return err};defer conn.Close()
	ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer stop()
	fmt.Printf("listening for NLS handshakes on %s; M1 limits enabled\n",files.record.Endpoint)
	return responder.Serve(ctx,conn,*ingress)
}

func usage() {
	fmt.Fprint(os.Stderr,`NLS NetOS router client
Usage:
  nls-router keygen --name NAME [--key-out router-key.pem] [--csr-out router.csr.pem]
  nls-router enroll --address HOST:PORT --tls-name DNS --ca-cert ca-cert.pem --ca-fingerprint SHA256 --name NAME [--key router-key.pem] [--csr router.csr.pem]
  nls-router control --address HOST:PORT --tls-name DNS --ca-cert ca-cert.pem --ca-fingerprint SHA256 [--cert router-cert.pem] [--key router-key.pem] [--state-dir /var/lib/nls-router]
  nls-router handshake --local-rdr local.rdr --control-address HOST:PORT --tls-name DNS --ca-cert ca-cert.pem --ca-fingerprint SHA256 --peer-id HEX --wan-address IPv6 --wan-prefix PREFIX --interface IFACE --dad-timeout DURATION --dad-poll-interval DURATION
  nls-router handshake-listen --local-rdr local.rdr --control-address HOST:PORT --tls-name DNS --ca-cert ca-cert.pem --ca-fingerprint SHA256 --ingress-interface IFACE --global-rate N --global-burst N --interface-rate N --interface-burst N --prefix-rate N --prefix-burst N --prefix-idle-ttl DURATION --max-tracked-prefixes N --max-pending N --max-pending-per-prefix N

Enrollment token is read only from NLS_ENROLLMENT_TOKEN.
`)
}
