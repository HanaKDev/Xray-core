package command_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/app/stats"
	. "github.com/xtls/xray-core/app/stats/command"
)

func TestDurableLedgerSurvivesLegacyStatsResetsAndRestart(t *testing.T) {
	ctx := context.Background()
	t.Setenv("XRAY_CATHODE_USAGE_JOURNAL", filepath.Join(t.TempDir(), "usage"))
	m, err := stats.NewManager(ctx, &stats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if m != nil {
			m.Close()
		}
	}()
	if err = m.Start(); err != nil {
		t.Fatal(err)
	}
	name := "user>>>legacy@example.test>>>traffic>>>uplink"
	c, err := m.RegisterCounter(name)
	if err != nil {
		t.Fatal(err)
	}
	s := NewStatsServer(m)
	c.Add(7)
	r, err := s.GetStats(ctx, &GetStatsRequest{Name: name, Reset_: true})
	if err != nil || r.Stat.Value != 7 || c.Value() != 0 {
		t.Fatal("legacy GetStats reset failed", r, err)
	}
	c.Add(11)
	q, err := s.QueryStats(ctx, &QueryStatsRequest{Pattern: "legacy@", Reset_: true})
	if err != nil || len(q.Stat) != 1 || q.Stat[0].Value != 11 || c.Value() != 0 {
		t.Fatal("legacy QueryStats reset failed", q, err)
	}
	c.Add(3)
	online, err := m.RegisterOnlineMap("user>>>legacy@example.test>>>online")
	if err != nil {
		t.Fatal(err)
	}
	online.AddIP("192.0.2.1")
	u, err := s.GetUsersStats(ctx, &GetUsersStatsRequest{Reset_: true, IncludeTraffic: true})
	if err != nil || len(u.Users) != 1 || u.Users[0].Traffic.Uplink != 3 || c.Value() != 0 {
		t.Fatal("legacy GetUsersStats reset failed", u, err)
	}
	before, err := m.Usage()
	if err != nil || len(before.Entries) != 1 || before.Entries[0].Bytes != 21 {
		t.Fatal("reset modified ledger", before, err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = stats.NewManager(ctx, &stats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	c, err = m.RegisterCounter(name)
	if err != nil || c.Value() != 0 {
		t.Fatal("historical bytes replayed into volatile collector", err)
	}
	c.Add(1)
	after, err := m.Usage()
	if err != nil || after.Ledger != before.Ledger || after.Entries[0].Date != before.Entries[0].Date || after.Entries[0].Bytes != 22 {
		t.Fatal("restart lost durable usage/date/ledger", after, err)
	}
}
