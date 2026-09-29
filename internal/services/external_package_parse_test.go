package services

import "testing"

// --- pip freeze ---

func TestParsePipFreeze_Normal(t *testing.T) {
	out := "requests==2.31.0\nflask==3.0.0\n"
	pkgs := ParsePipFreeze(out)
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if pkgs[0].Name != "requests" || pkgs[0].Version != "2.31.0" {
		t.Errorf("pkgs[0] = %+v", pkgs[0])
	}
}

func TestParsePipFreeze_EmptyAndMalformed(t *testing.T) {
	if pkgs := ParsePipFreeze(""); len(pkgs) != 0 {
		t.Errorf("empty input produced %d packages", len(pkgs))
	}
	out := "\nrequests==2.31.0\nmalformed-no-equals\n==\n"
	pkgs := ParsePipFreeze(out)
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1 (only the well-formed line)", len(pkgs))
	}
}

// --- npm list -g --depth=0 --json ---

func TestParseNpmListJSON_Normal(t *testing.T) {
	out := `{"dependencies":{"typescript":{"version":"5.4.2"},"eslint":{"version":"8.57.0"}}}`
	pkgs := ParseNpmListJSON(out)
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	found := map[string]string{}
	for _, p := range pkgs {
		found[p.Name] = p.Version
	}
	if found["typescript"] != "5.4.2" || found["eslint"] != "8.57.0" {
		t.Errorf("packages = %+v", found)
	}
}

func TestParseNpmListJSON_MalformedOrEmpty(t *testing.T) {
	if pkgs := ParseNpmListJSON(""); len(pkgs) != 0 {
		t.Errorf("empty input produced %d packages", len(pkgs))
	}
	if pkgs := ParseNpmListJSON("not json"); len(pkgs) != 0 {
		t.Errorf("malformed input produced %d packages", len(pkgs))
	}
	if pkgs := ParseNpmListJSON(`{"dependencies":{}}`); len(pkgs) != 0 {
		t.Errorf("no global packages produced %d packages", len(pkgs))
	}
}

// --- gem list --local ---

func TestParseGemList_Normal(t *testing.T) {
	out := "*** LOCAL GEMS ***\n\nbundler (2.4.10, 2.3.7)\nrake (13.1.0)\n"
	pkgs := ParseGemList(out)
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if pkgs[0].Name != "bundler" || pkgs[0].Version != "2.4.10" {
		t.Errorf("pkgs[0] = %+v, want newest (first-listed) version 2.4.10", pkgs[0])
	}
	if pkgs[1].Name != "rake" || pkgs[1].Version != "13.1.0" {
		t.Errorf("pkgs[1] = %+v", pkgs[1])
	}
}

func TestParseGemList_EmptyAndMalformed(t *testing.T) {
	if pkgs := ParseGemList(""); len(pkgs) != 0 {
		t.Errorf("empty input produced %d packages", len(pkgs))
	}
	out := "*** LOCAL GEMS ***\n\nmalformed-no-parens\n"
	if pkgs := ParseGemList(out); len(pkgs) != 0 {
		t.Errorf("malformed input produced %d packages", len(pkgs))
	}
}

// --- snap list ---

func TestParseSnapList_Normal(t *testing.T) {
	out := "Name    Version   Rev    Tracking       Publisher   Notes\n" +
		"core20  20231123  2015   latest/stable  canonical✓  base\n" +
		"lxd     5.21.2    28978  latest/stable  canonical✓  -\n"
	pkgs := ParseSnapList(out)
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if pkgs[0].Name != "core20" || pkgs[0].Version != "20231123" {
		t.Errorf("pkgs[0] = %+v", pkgs[0])
	}
}

func TestParseSnapList_EmptyOrHeaderOnly(t *testing.T) {
	if pkgs := ParseSnapList(""); len(pkgs) != 0 {
		t.Errorf("empty input produced %d packages", len(pkgs))
	}
	if pkgs := ParseSnapList("Name  Version  Rev  Tracking  Publisher  Notes\n"); len(pkgs) != 0 {
		t.Errorf("header-only input produced %d packages", len(pkgs))
	}
}
