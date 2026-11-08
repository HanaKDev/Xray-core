package stats

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDurableUsageTinyAndRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage")
	j, e := openUsage(path)
	if e != nil {
		t.Fatal(e)
	}
	name := "user>>>cred@example.test>>>traffic>>>uplink"
	j.add(name, 1)
	j.add(name, 37)
	id := j.id
	j.file.Close()
	j, e = openUsage(path)
	if e != nil {
		t.Fatal(e)
	}
	if j.id != id || j.totals[name] != 38 {
		t.Fatal("lost durable small counter")
	}
	j.file.Close()
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.WriteString("torn")
	f.Close()
	j, e = openUsage(path)
	if e != nil || j.totals[name] != 38 {
		t.Fatal("torn tail recovery failed", e)
	}
	j.file.Close()
	b, _ := os.ReadFile(path)
	b[14] ^= 1
	os.WriteFile(path, b, 0600)
	if j, e = openUsage(path); e == nil {
		j.file.Close()
		t.Fatal("corrupt committed record silently accepted")
	}
}

func TestDurableUsageCompactionDatesAndLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage")
	j, err := openUsage(path)
	if err != nil {
		t.Fatal(err)
	}
	name := "user>>>cred@example.test>>>traffic>>>downlink"
	old := usageRecord{Name: name, Date: "2026-01-01", Delta: 1}
	if err = j.write(old); err != nil {
		t.Fatal(err)
	}
	j.apply(old)
	j.nextCompact = 1
	j.add(name, 37)
	id := j.id
	if other, err := openUsage(path); err == nil {
		other.file.Close()
		t.Fatal("compacted journal allowed second writer")
	}
	j.file.Close()
	j, err = openUsage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.file.Close()
	if j.id != id || j.totals[name] != 38 || len(j.entries) != 2 {
		t.Fatal("compaction lost ledger, dates or bytes")
	}
	for _, v := range j.entries {
		if v.Date == "2026-01-01" && v.Bytes != 1 {
			t.Fatal("collection day changed")
		}
	}
}
