package appconfig

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.json")

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestDefaultPortalIsOffAndReachesTheMesh(t *testing.T) {
	config := Defaults()

	if config.Portal.Enabled {
		t.Fatal("the portal must be off by default")
	}

	if config.Portal.EffectiveReach() != ReachMesh {
		t.Fatalf("default reach = %q", config.Portal.EffectiveReach())
	}
}

func TestDefaultConfigStillSerialisesAsVersionOnly(t *testing.T) {
	data, err := json.Marshal(Defaults())
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != `{"version":1}` {
		t.Fatalf("default config = %s", data)
	}
}

func TestOldConfigFileWithoutPortalLoads(t *testing.T) {
	config, err := Load(writeConfig(t, `{"version":1}`))
	if err != nil {
		t.Fatal(err)
	}

	if config != Defaults() {
		t.Fatalf("config = %+v", config)
	}
}

func TestPortalSettingRoundTripsThroughSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	manager, err := OpenManager(path)
	if err != nil {
		t.Fatal(err)
	}

	want := Config{
		Version: CurrentVersion,
		Portal:  Portal{Enabled: true, Reach: ReachLAN},
	}

	if err := manager.Replace(want); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil || got != want {
		t.Fatalf("Load() = %+v, %v", got, err)
	}
}

func TestPortalValidation(t *testing.T) {
	valid := []Portal{
		{},
		{Enabled: true},
		{Enabled: true, Reach: ReachMesh},
		{Enabled: false, Reach: ReachLAN},
	}

	for _, portal := range valid {
		config := Config{Version: CurrentVersion, Portal: portal}

		if err := config.Validate(); err != nil {
			t.Errorf("Validate(%+v) error = %v", portal, err)
		}
	}

	invalid := []string{"internet", "LAN", "Mesh", "all", " lan", "lan ", "wan"}

	for _, reach := range invalid {
		config := Config{Version: CurrentVersion, Portal: Portal{Enabled: true, Reach: reach}}

		if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Validate(reach %q) error = %v; want ErrInvalidConfig", reach, err)
		}
	}
}

func TestLoadRejectsBadPortalSections(t *testing.T) {
	cases := map[string]string{
		"bad reach":       `{"version":1,"portal":{"enabled":true,"reach":"internet"}}`,
		"unknown field":   `{"version":1,"portal":{"enabled":true,"port":80}}`,
		"wrong type":      `{"version":1,"portal":{"enabled":"yes"}}`,
		"portal not obj":  `{"version":1,"portal":true}`,
		"reach not str":   `{"version":1,"portal":{"reach":1}}`,
		"wrong version":   `{"version":2,"portal":{"enabled":true}}`,
		"duplicate value": `{"version":1,"portal":{"enabled":true}} {"version":1}`,
	}

	for label, content := range cases {
		if _, err := Load(writeConfig(t, content)); err == nil {
			t.Errorf("%s: Load() accepted %s", label, content)
		}
	}
}

func TestEffectiveReachAppliesTheDefaultOnly(t *testing.T) {
	cases := map[string]string{
		"":        ReachMesh,
		ReachLAN:  ReachLAN,
		ReachMesh: ReachMesh,
	}

	for reach, want := range cases {
		if got := (Portal{Reach: reach}).EffectiveReach(); got != want {
			t.Errorf("EffectiveReach(%q) = %q; want %q", reach, got, want)
		}
	}
}
