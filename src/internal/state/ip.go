package state

import (
	"fmt"
	"time"
)

type IPState int

const (
	statePending IPState = iota
	stateAllowed
	stateDone
)

type DoneReason string

const (
	DoneDenied       DoneReason = "denied"
	DoneAutoRevoke   DoneReason = "automatic_revoke"
	DoneManualRevoke DoneReason = "manual_revoke"
)

type State interface {
	isState()
}

type PendingState struct {
	RequestedAt time.Time
	ExpiresAt   time.Time
	timer       *time.Timer
}

func (*PendingState) isState() {}

type AllowedState struct {
	approval Approval
}

func (*AllowedState) isState() {}

type DoneState struct {
	DoneAt time.Time
	Reason DoneReason
}

func (*DoneState) isState() {}

type Approval interface {
	GetExpiresAt() time.Time
	GetApprovedAt() time.Time
	GetTimer() *time.Timer
	SetTimer(t *time.Timer)
	Format() string
}

type ManualApproval struct {
	ExpiresAt  time.Time
	ApprovedAt time.Time
	timer      *time.Timer
}

func (m *ManualApproval) GetExpiresAt() time.Time { return m.ExpiresAt }
func (m *ManualApproval) GetApprovedAt() time.Time { return m.ApprovedAt }
func (m *ManualApproval) GetTimer() *time.Timer    { return m.timer }
func (m *ManualApproval) SetTimer(t *time.Timer)   { m.timer = t }
func (m *ManualApproval) Format() string            { return "Manual" }

type AutomaticApproval struct {
	ExpiresAt  time.Time
	ApprovedAt time.Time
	KeyName    string
	timer      *time.Timer
}

func (a *AutomaticApproval) GetExpiresAt() time.Time { return a.ExpiresAt }
func (a *AutomaticApproval) GetApprovedAt() time.Time { return a.ApprovedAt }
func (a *AutomaticApproval) GetTimer() *time.Timer    { return a.timer }
func (a *AutomaticApproval) SetTimer(t *time.Timer)   { a.timer = t }
func (a *AutomaticApproval) Format() string {
	return fmt.Sprintf("Automatic (%s)", a.KeyName)
}

type IP struct {
	ip       string
	lastSeen time.Time
	state    State
}

func (ip *IP) CanRequest() bool {
	switch ip.state.(type) {
	case *PendingState:
		return false
	case *AllowedState:
		return false
	case *DoneState:
		return ip.state.(*DoneState).Reason != DoneDenied
	}
	return true
}

func (ip *IP) IsCurrentlyAllowed(now time.Time) bool {
	if as, ok := ip.state.(*AllowedState); ok {
		return now.Before(as.approval.GetExpiresAt())
	}
	return false
}

func (ip *IP) Request(expiresAt time.Time, timer *time.Timer) {
	now := time.Now()
	ip.state = &PendingState{RequestedAt: now, ExpiresAt: expiresAt, timer: timer}
}

func (ip *IP) Approve(approval Approval) {
	switch s := ip.state.(type) {
	case *PendingState:
		if s.timer != nil {
			s.timer.Stop()
		}
	case *AllowedState:
		if s.approval.GetTimer() != nil {
			s.approval.GetTimer().Stop()
		}
	}
	ip.state = &AllowedState{approval: approval}
}

func (ip *IP) Deny() error {
	if _, ok := ip.state.(*PendingState); !ok {
		return fmt.Errorf("IP must be in Pending state to deny")
	}
	if ps, ok := ip.state.(*PendingState); ok && ps.timer != nil {
		ps.timer.Stop()
	}
	ip.state = &DoneState{DoneAt: time.Now(), Reason: DoneDenied}
	return nil
}

func (ip *IP) Revoke() error {
	if _, ok := ip.state.(*AllowedState); !ok {
		return fmt.Errorf("IP must be in Allowed state to revoke")
	}
	if as, ok := ip.state.(*AllowedState); ok && as.approval.GetTimer() != nil {
		as.approval.GetTimer().Stop()
	}
	ip.state = &DoneState{DoneAt: time.Now(), Reason: DoneManualRevoke}
	return nil
}

func (ip *IP) Timeout() {
	switch s := ip.state.(type) {
	case *PendingState:
		if s.timer != nil {
			s.timer.Stop()
		}
	case *AllowedState:
		if s.approval.GetTimer() != nil {
			s.approval.GetTimer().Stop()
		}
	}
	ip.state = &DoneState{DoneAt: time.Now(), Reason: DoneAutoRevoke}
}

func (ip *IP) UpdateLastSeen() { ip.lastSeen = time.Now() }

func (ip *IP) GetIP() string { return ip.ip }

func (ip *IP) GetLastSeen() time.Time { return ip.lastSeen }

func (ip *IP) GetApproval() (Approval, bool) {
	if as, ok := ip.state.(*AllowedState); ok {
		return as.approval, true
	}
	return nil, false
}

func (ip *IP) GetDoneReason() (DoneReason, bool) {
	if ds, ok := ip.state.(*DoneState); ok {
		return ds.Reason, true
	}
	return "", false
}

func (ip *IP) GetPendingRequestedAt() (time.Time, bool) {
	if ps, ok := ip.state.(*PendingState); ok {
		return ps.RequestedAt, true
	}
	return time.Time{}, false
}

func (ip *IP) GetPendingExpiresAt() (time.Time, bool) {
	if ps, ok := ip.state.(*PendingState); ok {
		return ps.ExpiresAt, true
	}
	return time.Time{}, false
}
