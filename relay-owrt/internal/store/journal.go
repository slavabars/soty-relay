package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/slavabars/soty-relay/relay-owrt/internal/wire"
)

const (
	journalName = "envelopes.ndjson"
	// A journal line is one envelope frame plus bookkeeping; keep the cap
	// above maxFrameBytes so a legitimate largest envelope still replays.
	maxJournalLine = 512 * 1024
)

const (
	recordEnvelope     = "m"
	recordSubscription = "s"
	recordRoot         = "r"
)

type journalRecord struct {
	T   string         `json:"t"`
	E   *wire.Envelope `json:"e,omitempty"`
	S   string         `json:"s,omitempty"`
	H   int            `json:"h,omitempty"`
	K   string         `json:"k,omitempty"`
	TS  int64          `json:"ts,omitempty"`
	C   int64          `json:"c,omitempty"`
	N   int            `json:"n,omitempty"`
	R   string         `json:"r,omitempty"`
	Pub string         `json:"pub,omitempty"`
	Sig string         `json:"sig,omitempty"`
}

type journal struct {
	path string
	f    *os.File
	w    *bufio.Writer
}

// openJournal reads every record and leaves the file open for appends.
// Long or malformed lines are skipped; an unreadable file fails loudly.
func openJournal(dir string) (*journal, []journalRecord, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create store directory: %w", err)
	}
	path := filepath.Join(dir, journalName)
	records, err := readJournal(path)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open journal: %w", err)
	}
	return &journal{path: path, f: f, w: bufio.NewWriterSize(f, 64*1024)},
		records, nil
}

func readJournal(path string) ([]journalRecord, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read journal: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxJournalLine)
	var out []journalRecord
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec journalRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan journal: %w", err)
	}
	return out, nil
}

func (j *journal) appendEnvelope(env *wire.Envelope, source string, hops int) error {
	return j.append(journalRecord{
		T: recordEnvelope, E: env, S: source, H: hops,
	})
}

func (j *journal) appendSubscription(key string, nowMs int64) error {
	return j.append(journalRecord{T: recordSubscription, K: key, TS: nowMs})
}

func (j *journal) append(rec journalRecord) error {
	if j == nil || j.f == nil {
		return nil
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if len(line)+1 > maxJournalLine {
		return errors.New("journal record is too large")
	}
	if _, err := j.w.Write(line); err != nil {
		return err
	}
	if err := j.w.WriteByte('\n'); err != nil {
		return err
	}
	return j.w.Flush()
}

// rewrite atomically replaces the journal with the given records. Used on
// prune and shutdown; compaction keeps replay time and flash use bounded.
func (j *journal) rewrite(recs []journalRecord) error {
	if j == nil {
		return nil
	}
	dir := filepath.Dir(j.path)
	tmp, err := os.CreateTemp(dir, ".envelopes-*.ndjson")
	if err != nil {
		return fmt.Errorf("create journal temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	w := bufio.NewWriterSize(tmp, 64*1024)
	for _, rec := range recs {
		line, err := json.Marshal(rec)
		if err != nil {
			tmp.Close()
			return err
		}
		if len(line)+1 > maxJournalLine {
			tmp.Close()
			return errors.New("journal record is too large")
		}
		if _, err := w.Write(line); err != nil {
			tmp.Close()
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, j.path); err != nil {
		return fmt.Errorf("replace journal: %w", err)
	}
	if err := j.w.Flush(); err != nil {
		return err
	}
	if err := j.f.Close(); err != nil {
		return err
	}
	f, err := os.OpenFile(j.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("reopen journal: %w", err)
	}
	j.f = f
	j.w = bufio.NewWriterSize(f, 64*1024)
	return nil
}

func (j *journal) size() int64 {
	if j == nil {
		return 0
	}
	info, err := os.Stat(j.path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func (j *journal) close() error {
	if j == nil || j.f == nil {
		return nil
	}
	if err := j.w.Flush(); err != nil {
		j.f.Close()
		return err
	}
	if err := j.f.Sync(); err != nil {
		j.f.Close()
		return err
	}
	return j.f.Close()
}
