package control

import (
	"sync"
	"time"
)

const DefaultControlLossTimeout = 300 * time.Second

type HealthState struct {
	LastSuccessUnixMS int64 `json:"last_success_unix_ms"`
	ControlUnavailable bool `json:"control_unavailable"`
	DropExistingSessions bool `json:"drop_existing_sessions"`
}

type LossGuard struct {
	mu sync.Mutex
	timeout time.Duration
	lastSuccess time.Time
	controlUnavailable bool
}

func NewLossGuard(timeout time.Duration) *LossGuard {
	if timeout <= 0 { timeout = DefaultControlLossTimeout }
	return &LossGuard{timeout: timeout}
}

func (g *LossGuard) MarkSuccess(now time.Time) HealthState {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lastSuccess = now
	g.controlUnavailable = false
	return g.state(now)
}

func (g *LossGuard) MarkFailure(now time.Time) HealthState {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.controlUnavailable = true
	return g.state(now)
}

func (g *LossGuard) Check(now time.Time) HealthState {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.lastSuccess.IsZero() && now.After(g.lastSuccess) && now.Sub(g.lastSuccess) > g.timeout {
		g.controlUnavailable = true
	}
	return g.state(now)
}

func (g *LossGuard) state(now time.Time) HealthState {
	out := HealthState{ControlUnavailable: g.controlUnavailable}
	if !g.lastSuccess.IsZero() {
		out.LastSuccessUnixMS = g.lastSuccess.UnixMilli()
		out.DropExistingSessions = g.controlUnavailable && now.After(g.lastSuccess) && now.Sub(g.lastSuccess) > g.timeout
	}
	return out
}
