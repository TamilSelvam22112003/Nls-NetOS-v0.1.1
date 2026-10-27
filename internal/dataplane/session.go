package dataplane

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TamilSelvam22112003/Nls-NetOS-v0.1.1/pkg/proto"
)

const minimumDatagramForHop = proto.V2HeaderSize + proto.V2AEADTagSize + 75

var (
	ErrSessionConfig       = errors.New("invalid NLS v2 established-session configuration")
	ErrSessionInactive     = errors.New("NLS v2 session is closed or expired")
	ErrSessionLimit        = errors.New("NLS v2 session packet, byte, or sequence limit reached")
	ErrSessionOuterTuple   = errors.New("NLS v2 packet outer tuple does not match the established endpoint")
	ErrSessionPeerIdentity = errors.New("NLS v2 hop identity does not match the authenticated peer")
	ErrSessionLocalIdentity = errors.New("NLS v2 session is not bound to this local router identity")
	ErrSessionUnknown      = errors.New("NLS v2 session token is unknown")
	ErrSessionConflict     = errors.New("NLS v2 session token or peer already has an active session")
	ErrSessionTableFull    = errors.New("NLS v2 session table is full")
)

// SessionConfig is handed to the dataplane only after the authenticated handshake,
// certificate/status checks and local policy have succeeded. It is not a wire message.
type SessionConfig struct {
	Token          [16]byte
	LocalIdentity  [32]byte
	PeerIdentity   [32]byte
	SendKey        []byte
	ReceiveKey     []byte
	KeyEpoch       uint32
	SendOuter      proto.OuterTuple
	ReceiveOuter   proto.OuterTuple
	ExpiresAt      time.Time
	MaxDatagram    uint32
	MaxPackets     uint64
	MaxBytes       uint64
}

// Session stores ephemeral directional keys and replay/sequence state in memory only.
// A Session MUST NOT be serialized or restored after process restart.
type Session struct {
	token         [16]byte
	localIdentity [32]byte
	peerIdentity  [32]byte
	sendKey       [32]byte
	receiveKey    [32]byte
	keyEpoch      uint32
	sendOuter     proto.OuterTuple
	receiveOuter  proto.OuterTuple
	expiresAt     time.Time
	maxDatagram   uint32
	maxPackets    uint64
	maxBytes      uint64

	sendMu       sync.Mutex
	receiveMu    sync.Mutex
	nextSequence uint64
	sentPackets  uint64
	sentBytes    uint64
	receivedPackets uint64
	receivedBytes   uint64
	replay       proto.ReplayWindow
	closed       atomic.Bool
}

// NewEstablishedSession validates the in-memory material and copies keys. The caller is
// responsible for ensuring the material came from a fully authenticated handshake; this
// constructor does not authenticate peers or verify Router-CA status evidence.
func NewEstablishedSession(config SessionConfig, now time.Time) (*Session, error) {
	if now.IsZero() || config.ExpiresAt.IsZero() || !config.ExpiresAt.After(now) ||
		config.ExpiresAt.Sub(now) > time.Hour ||
		allZero(config.Token[:]) || allZero(config.LocalIdentity[:]) || allZero(config.PeerIdentity[:]) ||
		config.LocalIdentity == config.PeerIdentity ||
		len(config.SendKey) != 32 || len(config.ReceiveKey) != 32 ||
		bytes.Equal(config.SendKey, config.ReceiveKey) ||
		config.MaxPackets == 0 || config.MaxBytes == 0 {
		return nil, ErrSessionConfig
	}
	if err := proto.ValidateOuterTuple(config.SendOuter); err != nil {
		return nil, fmt.Errorf("%w: send outer tuple: %v", ErrSessionConfig, err)
	}
	if err := proto.ValidateOuterTuple(config.ReceiveOuter); err != nil {
		return nil, fmt.Errorf("%w: receive outer tuple: %v", ErrSessionConfig, err)
	}
	if config.SendOuter.SourceIPv6 != config.ReceiveOuter.DestinationIPv6 ||
		config.SendOuter.DestinationIPv6 != config.ReceiveOuter.SourceIPv6 ||
		config.SendOuter.SourcePort != config.ReceiveOuter.DestinationPort ||
		config.SendOuter.DestinationPort != config.ReceiveOuter.SourcePort {
		return nil, fmt.Errorf("%w: send/receive endpoint tuples are not reciprocal", ErrSessionConfig)
	}
	if config.MaxDatagram == 0 {
		config.MaxDatagram = proto.V2DefaultMaxDatagram
	}
	if config.MaxDatagram < minimumDatagramForHop || config.MaxDatagram > proto.V2DefaultMaxDatagram {
		return nil, fmt.Errorf("%w: invalid maximum datagram size", ErrSessionConfig)
	}

	session := &Session{
		token:        config.Token,
		localIdentity: config.LocalIdentity,
		peerIdentity: config.PeerIdentity,
		keyEpoch:     config.KeyEpoch,
		sendOuter:    config.SendOuter,
		receiveOuter: config.ReceiveOuter,
		expiresAt:    config.ExpiresAt,
		maxDatagram:  config.MaxDatagram,
		maxPackets:   config.MaxPackets,
		maxBytes:     config.MaxBytes,
	}
	copy(session.sendKey[:], config.SendKey)
	copy(session.receiveKey[:], config.ReceiveKey)
	return session, nil
}

// SealHop encrypts one outbound hop wrapper. Sequence and byte counters are reserved
// before AEAD; any error after reservation burns that sequence number to prevent nonce reuse.
func (s *Session) SealHop(outer proto.OuterTuple, routeToken [16]byte, innerEnvelope []byte, now time.Time) ([]byte, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closed.Load() || now.IsZero() || !now.Before(s.expiresAt) {
		return nil, ErrSessionInactive
	}
	if !sameOuterTuple(outer, s.sendOuter) {
		return nil, ErrSessionOuterTuple
	}
	hop := proto.HopPlaintext{
		PreviousHopIdentity: s.localIdentity,
		PreviousHopLocator:  proto.LogicalLocatorForIdentity(s.localIdentity),
		RouteToken:          routeToken,
		InnerEnvelope:       append([]byte(nil), innerEnvelope...),
	}
	plaintext, err := proto.MarshalHopPlaintext(hop, s.maxDatagram)
	if err != nil {
		return nil, err
	}
	if s.sentPackets >= s.maxPackets || uint64(len(plaintext)) > s.maxBytes-s.sentBytes || s.nextSequence == ^uint64(0) {
		clear(plaintext)
		return nil, ErrSessionLimit
	}
	sequence := s.nextSequence
	s.nextSequence++
	s.sentPackets++
	s.sentBytes += uint64(len(plaintext))

	header := proto.V2Header{
		PacketType:   proto.V2PacketData,
		SessionToken: s.token,
		KeyEpoch:     s.keyEpoch,
		Sequence:     sequence,
	}
	datagram, err := proto.SealV2Data(s.sendKey[:], header, outer, plaintext, s.maxDatagram)
	clear(plaintext)
	if err != nil {
		return nil, err
	}
	return datagram, nil
}

// OpenHop authenticates a DATA datagram, commits replay state only after AEAD succeeds,
// parses the hop plaintext, and binds its claimed previous hop to the established peer.
func (s *Session) OpenHop(datagram []byte, outer proto.OuterTuple, now time.Time) (proto.V2Header, proto.HopPlaintext, error) {
	var zeroHeader proto.V2Header
	var zeroHop proto.HopPlaintext
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if s.closed.Load() || now.IsZero() || !now.Before(s.expiresAt) {
		return zeroHeader, zeroHop, ErrSessionInactive
	}
	if !sameOuterTuple(outer, s.receiveOuter) {
		return zeroHeader, zeroHop, ErrSessionOuterTuple
	}
	if s.receivedPackets >= s.maxPackets || s.receivedBytes >= s.maxBytes {
		return zeroHeader, zeroHop, ErrSessionLimit
	}
	header, plaintext, err := proto.OpenV2Data(s.receiveKey[:], datagram, outer, s.token, s.keyEpoch, &s.replay, s.maxDatagram)
	if err != nil {
		return zeroHeader, zeroHop, err
	}
	defer clear(plaintext)
	if uint64(len(plaintext)) > s.maxBytes-s.receivedBytes {
		return zeroHeader, zeroHop, ErrSessionLimit
	}
	hop, err := proto.ParseHopPlaintext(plaintext, s.maxDatagram)
	if err != nil {
		return zeroHeader, zeroHop, err
	}
	if hop.PreviousHopIdentity != s.peerIdentity {
		return zeroHeader, zeroHop, ErrSessionPeerIdentity
	}
	s.receivedPackets++
	s.receivedBytes += uint64(len(plaintext))
	return header, hop, nil
}

// Close invalidates the session and best-effort clears in-memory key copies.
// Session state must never be restored after a process restart.
func (s *Session) Close() {
	if s == nil {
		return
	}
	s.closed.Store(true)
	s.sendMu.Lock()
	clear(s.sendKey[:])
	s.sendMu.Unlock()
	s.receiveMu.Lock()
	clear(s.receiveKey[:])
	s.receiveMu.Unlock()
}

func (s *Session) IsActive(now time.Time) bool {
	return s != nil && !s.closed.Load() && !now.IsZero() && now.Before(s.expiresAt)
}

func (s *Session) Token() [16]byte { return s.token }
func (s *Session) LocalIdentity() [32]byte { return s.localIdentity }
func (s *Session) PeerIdentity() [32]byte { return s.peerIdentity }
func (s *Session) SendOuter() proto.OuterTuple { return s.sendOuter }
func (s *Session) ReceiveOuter() proto.OuterTuple { return s.receiveOuter }
func (s *Session) ExpiresAt() time.Time { return s.expiresAt }

func sameOuterTuple(left, right proto.OuterTuple) bool {
	return left.SourceIPv6 == right.SourceIPv6 &&
		left.DestinationIPv6 == right.DestinationIPv6 &&
		left.SourcePort == right.SourcePort &&
		left.DestinationPort == right.DestinationPort
}

func allZero(value []byte) bool {
	var combined byte
	for _, b := range value {
		combined |= b
	}
	return combined == 0
}
