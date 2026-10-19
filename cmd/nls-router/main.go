package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/TamilSelvam22112003/Nls-NetOS-v0.1.1/internal/control"
	"github.com/TamilSelvam22112003/Nls-NetOS-v0.1.1/internal/enrollment"
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

func usage() {
	fmt.Fprint(os.Stderr,`NLS NetOS router client
Usage:
  nls-router keygen --name NAME [--key-out router-key.pem] [--csr-out router.csr.pem]
  nls-router enroll --address HOST:PORT --tls-name DNS --ca-cert ca-cert.pem --ca-fingerprint SHA256 --name NAME [--key router-key.pem] [--csr router.csr.pem]
  nls-router control --address HOST:PORT --tls-name DNS --ca-cert ca-cert.pem --ca-fingerprint SHA256 [--cert router-cert.pem] [--key router-key.pem] [--state-dir /var/lib/nls-router]

Enrollment token is read only from NLS_ENROLLMENT_TOKEN.
`)
}
