// Cathode's opt-in durable counter-event journal. The accounting boundary is
// Counter.Add, not a claim about bytes in an in-flight network syscall.
package stats

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type UsageEntry struct {
	Date      string `json:"date"`
	Email     string `json:"email"`
	Direction string `json:"direction"`
	Bytes     int64  `json:"bytes"`
}
type UsageSnapshot struct {
	Ledger    string       `json:"ledger"`
	Collected int64        `json:"collected_ms"`
	Entries   []UsageEntry `json:"entries"`
	Size      int64        `json:"journal_bytes"`
	Limit     int64        `json:"journal_limit"`
}
type usageRecord struct {
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Date  string `json:"date,omitempty"`
	Delta int64  `json:"delta,omitempty"`
}
type usageJournal struct {
	mu          sync.Mutex
	file        *os.File
	path        string
	nextCompact int64
	id          string
	size        int64
	totals      map[string]int64
	entries     map[string]UsageEntry
}

func openUsage(path string) (*usageJournal, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*usageJournal, error) { f.Close(); return nil, e }
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return fail(e)
	}
	j := &usageJournal{file: f, path: path, nextCompact: 64 << 20, totals: map[string]int64{}, entries: map[string]UsageEntry{}}
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, e := r.ReadBytes('\n')
		if e == io.EOF {
			if len(line) > 0 {
				if e = f.Truncate(j.size); e != nil {
					return fail(e)
				}
				if e = f.Sync(); e != nil {
					return fail(e)
				}
			}
			break
		}
		if e != nil {
			return fail(e)
		}
		if len(line) < 10 || len(line) > 65536 {
			return fail(errors.New("corrupt usage journal"))
		}
		var crc uint32
		if _, e = fmt.Sscanf(string(line[:8]), "%08x", &crc); e != nil || line[8] != ' ' || crc32.ChecksumIEEE(line[9:len(line)-1]) != crc {
			return fail(errors.New("usage journal checksum mismatch"))
		}
		var rec usageRecord
		if e = json.Unmarshal(line[9:len(line)-1], &rec); e != nil {
			return fail(e)
		}
		if j.size == 0 {
			if rec.ID == "" {
				return fail(errors.New("missing ledger identity"))
			}
			j.id = rec.ID
		} else {
			if rec.ID != "" || rec.Delta <= 0 || !strings.HasPrefix(rec.Name, "user>>>") {
				return fail(errors.New("invalid usage record"))
			}
			j.apply(rec)
		}
		j.size += int64(len(line))
	}
	if _, e = f.Seek(0, io.SeekEnd); e != nil {
		return fail(e)
	}
	if j.id == "" {
		var b [16]byte
		if _, e = rand.Read(b[:]); e != nil {
			return fail(e)
		}
		j.id = hex.EncodeToString(b[:])
		if e = j.write(usageRecord{ID: j.id}); e != nil {
			return fail(e)
		}
		dir, e := os.Open(filepath.Dir(path))
		if e != nil {
			return fail(e)
		}
		e = dir.Sync()
		dir.Close()
		if e != nil {
			return fail(e)
		}
	}
	return j, nil
}
func (j *usageJournal) write(r usageRecord) error {
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	line := []byte(fmt.Sprintf("%08x %s\n", crc32.ChecksumIEEE(b), b))
	if j.size+int64(len(line)) > 1<<30 {
		return errors.New("usage journal full; fail-stop, archive before restarting")
	}
	n, e := j.file.Write(line)
	if e != nil {
		return e
	}
	if n != len(line) {
		return io.ErrShortWrite
	}
	if e = j.file.Sync(); e != nil {
		return e
	}
	j.size += int64(n)
	return nil
}
func (j *usageJournal) apply(r usageRecord) {
	j.totals[r.Name] += r.Delta
	p := strings.Split(r.Name, ">>>")
	if len(p) != 4 {
		return
	}
	k := r.Date + "|" + p[1] + "|" + p[3]
	v := j.entries[k]
	v.Date = r.Date
	v.Email = p[1]
	v.Direction = p[3]
	v.Bytes += r.Delta
	j.entries[k] = v
}
func (j *usageJournal) add(name string, delta int64) {
	if delta == 0 {
		return
	}
	if delta < 0 {
		panic("durable user counters require positive deltas")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.size >= j.nextCompact {
		if err := j.compact(); err != nil {
			panic(fmt.Errorf("durable usage compaction failed: %w", err))
		}
		j.nextCompact = max(64<<20, j.size*2)
	}
	r := usageRecord{Name: name, Date: time.Now().UTC().Add(8 * time.Hour).Format("2006-01-02"), Delta: delta}
	if e := j.write(r); e != nil {
		panic(fmt.Errorf("durable usage unavailable: %w", e))
	}
	j.apply(r)
}
func (m *Manager) Usage() (UsageSnapshot, error) {
	j := m.usage
	if j == nil {
		return UsageSnapshot{}, errors.New("durable usage is not enabled")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	s := UsageSnapshot{Ledger: j.id, Collected: time.Now().UnixMilli(), Size: j.size, Limit: 1 << 30, Entries: []UsageEntry{}}
	for _, v := range j.entries {
		s.Entries = append(s.Entries, v)
	}
	return s, nil
}

// compact atomically replaces the event history with equivalent per-day totals.
// Both old and new inodes stay locked across rename, so another process cannot
// open either generation as a writer during the transition.
func (j *usageJournal) compact() error {
	path := j.path
	f, err := os.CreateTemp(filepath.Dir(path), ".usage-compact-*")
	if err != nil {
		return err
	}
	name := f.Name()
	keep := false
	defer func() {
		if !keep {
			f.Close()
			os.Remove(name)
		}
	}()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return err
	}
	next := &usageJournal{file: f}
	if err = next.write(usageRecord{ID: j.id}); err != nil {
		return err
	}
	for _, v := range j.entries {
		if err = next.write(usageRecord{Name: "user>>>" + v.Email + ">>>traffic>>>" + v.Direction, Date: v.Date, Delta: v.Bytes}); err != nil {
			return err
		}
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	// Name() must remain the durable pathname for the next compaction.
	old := j.file
	j.file = f
	j.path = path
	j.size = next.size
	keep = true
	old.Close()
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
