package policy

import "testing"

type fakeProcs map[uint32]Proc

func (f fakeProcs) Lookup(pid uint32) (Proc, bool) { p, ok := f[pid]; return p, ok }

func TestTwoInstancesOfSameExecutableGetDifferentPolicy(t *testing.T) {
	procs := fakeProcs{
		100: {PID: 100, Created: 10, Path: `C:\app\tool.exe`},
		200: {PID: 200, Created: 20, Path: `C:\app\tool.exe`},
	}
	s := &Set{Rules: []Rule{{ID: "a", Kind: KindInstance, PID: 100, Created: 10, Enabled: true}}}
	if _, ok := s.Match(procs, 100); !ok {
		t.Fatal("selected instance not matched")
	}
	if _, ok := s.Match(procs, 200); ok {
		t.Fatal("sibling instance of the same executable must not be matched")
	}
}

func TestRecycledPIDDoesNotInheritInstanceRule(t *testing.T) {
	s := &Set{Rules: []Rule{{ID: "a", Kind: KindInstance, PID: 100, Created: 10, Enabled: true}}}
	reused := fakeProcs{100: {PID: 100, Created: 999, Path: `C:\other.exe`}}
	if _, ok := s.Match(reused, 100); ok {
		t.Fatal("a new process that reused the PID must not match")
	}
}

func TestExecutableRuleIsCaseInsensitiveAndCoversLaterLaunches(t *testing.T) {
	s := &Set{Rules: []Rule{{ID: "x", Kind: KindExecutable, Path: `C:\Apps\Tool.EXE`, Enabled: true}}}
	procs := fakeProcs{300: {PID: 300, Created: 30, Path: `c:\apps\tool.exe`}}
	if _, ok := s.Match(procs, 300); !ok {
		t.Fatal("executable rule should match regardless of case")
	}
}

func TestChildrenOnlyWhenRequested(t *testing.T) {
	procs := fakeProcs{
		1: {PID: 1, Created: 10, Path: `C:\p\parent.exe`},
		2: {PID: 2, Created: 20, Parent: 1, Path: `C:\p\child.exe`},
		3: {PID: 3, Created: 30, Parent: 2, Path: `C:\p\grandchild.exe`},
	}
	with := &Set{Rules: []Rule{{ID: "r", Kind: KindExecutable, Path: `C:\p\parent.exe`, Children: true, Enabled: true}}}
	if _, ok := with.Match(procs, 3); !ok {
		t.Fatal("grandchild should be selected when Children is set")
	}
	without := &Set{Rules: []Rule{{ID: "r", Kind: KindExecutable, Path: `C:\p\parent.exe`, Enabled: true}}}
	if _, ok := without.Match(procs, 2); ok {
		t.Fatal("child must not be selected when Children is unset")
	}
}

func TestParentWithRecycledPIDIsNotTrusted(t *testing.T) {
	// The recorded parent PID now belongs to a process that started after the child.
	procs := fakeProcs{
		1: {PID: 1, Created: 500, Path: `C:\p\parent.exe`},
		2: {PID: 2, Created: 20, Parent: 1, Path: `C:\p\child.exe`},
	}
	s := &Set{Rules: []Rule{{ID: "r", Kind: KindExecutable, Path: `C:\p\parent.exe`, Children: true, Enabled: true}}}
	if _, ok := s.Match(procs, 2); ok {
		t.Fatal("a recycled parent PID must not select the child")
	}
}

func TestCommandLineFilterSeparatesBrowserProfiles(t *testing.T) {
	procs := fakeProcs{
		10: {PID: 10, Created: 1, Path: `C:\chrome.exe`, Cmd: `chrome.exe --user-data-dir=C:\tp\profile`},
		11: {PID: 11, Created: 2, Path: `C:\chrome.exe`, Cmd: `chrome.exe`},
	}
	s := &Set{Rules: []Rule{{ID: "c", Kind: KindExecutable, Path: `C:\chrome.exe`, CmdContains: `C:\tp\profile`, Enabled: true}}}
	if _, ok := s.Match(procs, 10); !ok {
		t.Fatal("profile instance should match")
	}
	if _, ok := s.Match(procs, 11); ok {
		t.Fatal("ordinary Chrome must not match")
	}
}

func TestDisabledRulesMatchNothing(t *testing.T) {
	procs := fakeProcs{1: {PID: 1, Created: 1, Path: `C:\a.exe`}}
	s := &Set{Rules: []Rule{{ID: "r", Kind: KindExecutable, Path: `C:\a.exe`}}}
	if _, ok := s.Match(procs, 1); ok {
		t.Fatal("disabled rule matched")
	}
}
