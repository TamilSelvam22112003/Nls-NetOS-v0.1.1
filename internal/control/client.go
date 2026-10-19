// Package control implements the router's TLS 1.3 mutual-authenticated control client.
package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	tlvHeartbeat uint16 = 0x0001
	tlvHeartbeatAck uint16 = 0x0002
	tlvPolicySync uint16 = 0x0020
	tlvPolicyAck uint16 = 0x0021
	tlvRevocationPush uint16 = 0x0030
)

type Options struct {
	Address string
	ServerName string
	RootCertificatePath string
	RootFingerprint string
	CertificatePath string
	PrivateKeyPath string
	StateDir string
	Interval time.Duration
	ControlLossTimeout time.Duration
}

type PolicyEntry struct {
	Action uint8 `json:"action"`
	Prefix string `json:"prefix"`
}
type PolicyState struct {
	Generation uint64 `json:"generation"`
	Entries []PolicyEntry `json:"entries"`
}
type RevocationEntry struct {
	RouterID string `json:"router_id"`
	Status uint8 `json:"status"`
	EffectiveUnixMS uint64 `json:"effective_unix_ms"`
}
type RevocationState struct {
	Generation uint64 `json:"generation"`
	Entries []RevocationEntry `json:"entries"`
}

func Run(ctx context.Context,o Options)error {
	if o.Address==""||o.ServerName==""||o.RootCertificatePath==""||o.RootFingerprint==""||o.CertificatePath==""||o.PrivateKeyPath==""||o.StateDir=="" {
		return errors.New("address, TLS name, CA certificate/fingerprint, router certificate/key, and state directory are required")
	}
	if o.Interval<=0{o.Interval=5*time.Second}
	if o.ControlLossTimeout<=0{o.ControlLossTimeout=DefaultControlLossTimeout}
	rootPEM,err:=os.ReadFile(o.RootCertificatePath);if err!=nil{return err}
	block,_:=pemDecode(rootPEM);if block==nil{return errors.New("invalid CA root certificate")}
	root,err:=x509.ParseCertificate(block);if err!=nil{return err}
	pin,err:=hex.DecodeString(strings.TrimSpace(o.RootFingerprint));if err!=nil||len(pin)!=sha256.Size{return errors.New("CA fingerprint must be 64 hex characters")}
	sum:=sha256.Sum256(root.Raw);if !bytes.Equal(pin,sum[:]){return errors.New("CA root fingerprint pin mismatch")}
	roots:=x509.NewCertPool();roots.AddCert(root)
	clientCert,err:=tls.LoadX509KeyPair(o.CertificatePath,o.PrivateKeyPath);if err!=nil{return err}
	if err=os.MkdirAll(o.StateDir,0700);err!=nil{return err}
	if err=os.Chmod(o.StateDir,0700);err!=nil{return err}
	policyPath:=filepath.Join(o.StateDir,"policy.json")
	revPath:=filepath.Join(o.StateDir,"revocations.json")
	healthPath:=filepath.Join(o.StateDir,"control-status.json")
	guard:=NewLossGuard(o.ControlLossTimeout)
	publish:=func(state HealthState){_ = writeJSONAtomic(healthPath,state,0600)}
	for {
		if ctx.Err()!=nil{return nil}
		cfg:=&tls.Config{RootCAs:roots,ServerName:o.ServerName,Certificates:[]tls.Certificate{clientCert},MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13}
		dialer:=net.Dialer{Timeout:10*time.Second}
		conn,err:=tls.DialWithDialer(&dialer,"tcp",o.Address,cfg)
		if err==nil {
			_ = runSession(ctx,conn,o.Interval,policyPath,revPath,func(now time.Time){publish(guard.MarkSuccess(now))})
			_ = conn.Close()
		}
		if ctx.Err()!=nil{return nil}
		publish(guard.MarkFailure(time.Now()))
		// Control outages are recoverable: reconnect instead of exiting. The
		// persisted health state flags sessions for teardown after the ADR-0007 deadline.
		select{case <-ctx.Done():return nil;case <-time.After(o.Interval):}
	}
}

func runSession(ctx context.Context,conn net.Conn,interval time.Duration,policyPath,revPath string,onSync func(time.Time))error {
	ticker:=time.NewTicker(interval);defer ticker.Stop()
	for {
		if ctx.Err()!=nil{return nil}
		var random [8]byte
		if _,err:=rand.Read(random[:]);err!=nil{return err}
		requestID:=binary.BigEndian.Uint64(random[:]);if requestID==0{requestID=1}
		now:=uint64(time.Now().UnixMilli())
		lastRev:=uint64(0)
		if state,err:=loadRevocations(revPath);err==nil{lastRev=state.Generation}else if !errors.Is(err,os.ErrNotExist){return err}
		heartbeat:=make([]byte,32)
		binary.BigEndian.PutUint64(heartbeat[:8],requestID)
		binary.BigEndian.PutUint64(heartbeat[8:16],now)
		binary.BigEndian.PutUint64(heartbeat[16:24],now)
		binary.BigEndian.PutUint64(heartbeat[24:32],lastRev)
		_ = conn.SetDeadline(time.Now().Add(15*time.Second))
		if err:=writeTLV(conn,tlvHeartbeat,heartbeat);err!=nil{return err}
		typ,ack,err:=readTLV(conn,128);if err!=nil{return err}
		if typ!=tlvHeartbeatAck||len(ack)!=40||binary.BigEndian.Uint64(ack[:8])!=requestID||binary.BigEndian.Uint64(ack[8:16])!=now||binary.BigEndian.Uint64(ack[16:24])!=now||binary.BigEndian.Uint64(ack[32:40])==0{return errors.New("invalid heartbeat acknowledgement")}
		typ,policyBytes,err:=readTLV(conn,1<<20);if err!=nil{return err}
		if typ!=tlvPolicySync{return errors.New("expected POLICY_SYNC")}
		policy,parseErr:=parsePolicy(policyBytes)
		if parseErr==nil {
			current,loadErr:=loadPolicy(policyPath)
			if loadErr!=nil&&!errors.Is(loadErr,os.ErrNotExist){parseErr=loadErr}else if loadErr==nil&&policy.Generation<current.Generation{parseErr=errors.New("stale policy generation")}
		}
		status,code:=uint16(0),uint16(0)
		if parseErr!=nil{status,code=1,1}else if err=writeJSONAtomic(policyPath,policy,0600);err!=nil{status,code=1,0x0016}
		if err=writeTLV(conn,tlvPolicyAck,policyAck(policy.Generation,status,code));err!=nil{return err}
		if status!=0{return fmt.Errorf("policy sync rejected: %v",parseErr)}
		// Revocation updates are only sent when the server generation is newer than lastRev.
		typ,revBytes,err:=readTLV(conn,1<<22);if err!=nil{return err}
		if typ==tlvRevocationPush {
			rev,parseErr:=parseRevocations(revBytes)
			if parseErr==nil&&rev.Generation<lastRev{parseErr=errors.New("stale revocation generation")}
			currentRev,currentErr:=loadRevocations(revPath)
			if parseErr==nil&&rev.Generation==lastRev {
				if currentErr!=nil||!reflect.DeepEqual(currentRev,rev){parseErr=errors.New("revocation state changed without a generation increase")}
			}
			status,code=0,0
			if parseErr!=nil{status,code=1,1}else if rev.Generation>lastRev { if err=writeJSONAtomic(revPath,rev,0600);err!=nil{status,code=1,0x0016} }
			if err=writeTLV(conn,tlvPolicyAck,policyAck(rev.Generation,status,code));err!=nil{return err}
			if status!=0{return fmt.Errorf("revocation sync rejected: %v",parseErr)}
			if onSync!=nil { onSync(time.Now()) }
		} else {
			// A missing push is not legal in this version; it means the server and client disagree on generation state.
			return errors.New("expected REVOCATION_PUSH")
		}
		select{case <-ctx.Done():return nil;case <-ticker.C:}
	}
}

func parsePolicy(value []byte)(PolicyState,error) {
	var out PolicyState
	if len(value)<12{return out,errors.New("truncated policy sync")}
	out.Generation=binary.BigEndian.Uint64(value[:8]);count:=binary.BigEndian.Uint32(value[8:12])
	if out.Generation==0||count==0{return out,errors.New("policy generation and entry count must be nonzero")}
	if count>4096{return out,errors.New("policy entry count exceeds limit")}
	offset:=12
	seen:=map[string]uint8{}
	var previous string
	prefixes:=make([]netip.Prefix,0,count)
	for i:=uint32(0);i<count;i++ {
		if len(value)-offset<4{return out,errors.New("truncated policy entry")}
		action,family,bits,reserved:=value[offset],value[offset+1],int(value[offset+2]),value[offset+3];offset+=4
		if reserved!=0||(action!=1&&action!=2){return out,errors.New("invalid policy action or reserved byte")}
		addrLen:=0;maxBits:=0
		if family==4{addrLen,maxBits=4,32}else if family==6{addrLen,maxBits=16,128}else{return out,errors.New("invalid policy address family")}
		if len(value)-offset<addrLen{return out,errors.New("truncated policy address")}
		if bits<0||bits>maxBits{return out,errors.New("invalid policy prefix length")}
		var addr netip.Addr
		if family==4{var b [4]byte;copy(b[:],value[offset:offset+4]);addr=netip.AddrFrom4(b)}else{var b [16]byte;copy(b[:],value[offset:offset+16]);addr=netip.AddrFrom16(b)}
		offset+=addrLen
		p:=netip.PrefixFrom(addr,bits)
		if p.Masked().Addr()!=addr{return out,errors.New("policy prefix has host bits set")}
		key:=p.String()
		if _,ok:=seen[key];ok{return out,errors.New("duplicate policy prefix")}
		if previous!=""&&key<previous{return out,errors.New("policy entries are not sorted")}
		previous=key;seen[key]=action
		prefixes=append(prefixes,p)
		out.Entries=append(out.Entries,PolicyEntry{Action:action,Prefix:key})
	}
	if offset!=len(value){return out,errors.New("trailing policy bytes")}
	for i,p:=range prefixes{for j:=0;j<i;j++{q:=prefixes[j];if seen[p.String()]!=seen[q.String()]&&(p.Contains(q.Addr())||q.Contains(p.Addr())){return out,errors.New("conflicting overlapping policy prefixes")}}}
	return out,nil
}

func parseRevocations(value []byte)(RevocationState,error) {
	var out RevocationState
	if len(value)<12{return out,errors.New("truncated revocation push")}
	out.Generation=binary.BigEndian.Uint64(value[:8]);count:=binary.BigEndian.Uint32(value[8:12])
	if out.Generation==0{return out,errors.New("revocation generation must be nonzero")}
	if count>65536||uint64(len(value))!=12+uint64(count)*32{return out,errors.New("invalid revocation push length/count")}
	offset:=12;last:=""
	for i:=uint32(0);i<count;i++ {
		id:=hex.EncodeToString(value[offset:offset+16]);status:=value[offset+16]
		for _,b:=range value[offset+17:offset+24]{if b!=0{return out,errors.New("nonzero revocation reserved byte")}}
		effective:=binary.BigEndian.Uint64(value[offset+24:offset+32]);offset+=32
		if status<1||status>3{return out,errors.New("invalid revocation status")}
		if last!=""&&id<=last{return out,errors.New("revocation entries not sorted and unique")}
		last=id
		out.Entries=append(out.Entries,RevocationEntry{RouterID:id,Status:status,EffectiveUnixMS:effective})
	}
	return out,nil
}

func policyAck(generation uint64,status,code uint16)[]byte {
	b:=make([]byte,12);binary.BigEndian.PutUint64(b[:8],generation);binary.BigEndian.PutUint16(b[8:10],status);binary.BigEndian.PutUint16(b[10:12],code);return b
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
func writeFull(w io.Writer,b []byte)error{for len(b)>0{n,err:=w.Write(b);if err!=nil{return err};if n==0{return io.ErrShortWrite};b=b[n:]};return nil}
func writeJSONAtomic(path string,v any,mode os.FileMode)error {
	data,err:=json.MarshalIndent(v,"","  ");if err!=nil{return err};data=append(data,byte(10))
	if err=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return err}
	f,err:=os.CreateTemp(filepath.Dir(path),".nls-state-*");if err!=nil{return err};tmp:=f.Name();defer os.Remove(tmp)
	if err=f.Chmod(mode);err!=nil{_ = f.Close();return err}
	if err=writeFull(f,data);err!=nil{_ = f.Close();return err}
	if err=f.Sync();err!=nil{_ = f.Close();return err};if err=f.Close();err!=nil{return err}
	if err=os.Rename(tmp,path);err!=nil{return err}
	d,err:=os.Open(filepath.Dir(path));if err==nil{_ = d.Sync();_ = d.Close()};return nil
}
func loadPolicy(path string)(PolicyState,error){var v PolicyState;b,e:=os.ReadFile(path);if e!=nil{return v,e};e=json.Unmarshal(b,&v);return v,e}
func loadRevocations(path string)(RevocationState,error){var v RevocationState;b,e:=os.ReadFile(path);if e!=nil{return v,e};e=json.Unmarshal(b,&v);return v,e}
func pemDecode(b []byte)([]byte,error){block,_:=pem.Decode(b);if block==nil||block.Type!="CERTIFICATE"{return nil,errors.New("invalid certificate PEM")};return block.Bytes,nil}

// SortedPrefixes returns a stable representation useful to diagnostics and tests.
func SortedPrefixes(entries []PolicyEntry) []PolicyEntry {out:=append([]PolicyEntry(nil),entries...);sort.Slice(out,func(i,j int)bool{return out[i].Prefix<out[j].Prefix});return out}
