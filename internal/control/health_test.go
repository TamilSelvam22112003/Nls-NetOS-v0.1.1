package control

import (
 "testing"
 "time"
)

func TestControlLossDeadlineIsStrictlyGreaterThanThreshold(t *testing.T) {
 start:=time.Unix(1800000000,0);g:=NewLossGuard(300*time.Second);g.MarkSuccess(start)
 cases:=[]struct{name string;elapsed time.Duration;want bool}{{"before",299*time.Second,false},{"exactly at threshold",300*time.Second,false},{"after threshold",300*time.Second+time.Nanosecond,true}}
 for _,tc:=range cases { t.Run(tc.name,func(t *testing.T){state:=g.MarkFailure(start.Add(tc.elapsed));if state.DropExistingSessions!=tc.want{t.Fatalf("drop=%v want=%v",state.DropExistingSessions,tc.want)}}) }
}
func TestControlRecoveryClearsLossState(t *testing.T) {
 start:=time.Unix(1800000000,0);g:=NewLossGuard(300*time.Second);g.MarkSuccess(start)
 if !g.MarkFailure(start.Add(301*time.Second)).DropExistingSessions{t.Fatal("control loss should expire sessions")}
 recovered:=g.MarkSuccess(start.Add(302*time.Second));if recovered.DropExistingSessions||recovered.ControlUnavailable||recovered.LastSuccessUnixMS!=start.Add(302*time.Second).UnixMilli(){t.Fatalf("bad recovered state %#v",recovered)}
}
func TestNoPriorControlSuccessDoesNotClaimExistingSessions(t *testing.T) {
 g:=NewLossGuard(300*time.Second);state:=g.MarkFailure(time.Unix(1800000000,0).Add(time.Hour));if state.DropExistingSessions||state.LastSuccessUnixMS!=0{t.Fatalf("unexpected state %#v",state)}
}

func TestControlLossWatchdogExpiresSessionWithoutSocketError(t *testing.T) {
	start:=time.Unix(1800000000,0)
	g:=NewLossGuard(300*time.Second)
	g.MarkSuccess(start)
	if state:=g.Check(start.Add(300*time.Second));state.DropExistingSessions{t.Fatal("must not drop at exact threshold")}
	if state:=g.Check(start.Add(301*time.Second));!state.DropExistingSessions||!state.ControlUnavailable{t.Fatalf("watchdog failed to expire session: %#v",state)}
}
