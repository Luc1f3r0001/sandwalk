package manifest

import (
	"database/sql"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed file manifest.
type Store struct {
	db *sql.DB
}

// Open opens (and initializes) the manifest database.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // sqlite single-writer
	if _, err := db.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA journal_size_limit=67108864;
		PRAGMA busy_timeout=5000;
		CREATE TABLE IF NOT EXISTS manifest (
			path            TEXT PRIMARY KEY,
			size            INTEGER NOT NULL,
			ctime_ns        INTEGER NOT NULL,
			inode           INTEGER NOT NULL,
			last_scanned    TEXT NOT NULL,
			ruleset_version TEXT NOT NULL
		);
	`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Plan walks the roots and decides which files need (re)scanning. A file is
// scanned when it is new, when its size/ctime/inode changed, or when the ruleset
// version changed since it was last scanned. It also returns the set of paths
// seen on disk (for deletion detection) and the paths deleted since last sweep.
func (s *Store) Plan(roots, excludes []string, rulesetVersion string) (toScan []string, gitRepos []string, deleted []string, err error) {
	// Load existing manifest into memory for fast comparison.
	prev := map[string]FileKey{}
	prevRuleset := map[string]string{}
	rows, err := s.db.Query(`SELECT path, size, ctime_ns, inode, ruleset_version FROM manifest`)
	if err != nil {
		return nil, nil, nil, err
	}
	for rows.Next() {
		var p, rv string
		var k FileKey
		if err := rows.Scan(&p, &k.Size, &k.CtimeNs, &k.Inode, &rv); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		prev[p] = k
		prevRuleset[p] = rv
	}
	rows.Close()

	seen := map[string]bool{}
	walkRegularFiles(roots, excludes,
		func(path string, key FileKey) {
			seen[path] = true
			old, existed := prev[path]
			if !existed || old != key || prevRuleset[path] != rulesetVersion {
				toScan = append(toScan, path)
			}
		},
		func(repo string, key FileKey) {
			// Track each git repo's history state under a "git:" key. Re-scan its
			// history only when the reflog/.git changed or the ruleset changed.
			gk := "git:" + repo
			seen[gk] = true
			old, existed := prev[gk]
			if !existed || old != key || prevRuleset[gk] != rulesetVersion {
				gitRepos = append(gitRepos, repo)
			}
		},
	)

	// Deleted = in manifest but no longer seen. A path is considered deleted if:
	// (a) it was under a walked root but not seen on this walk (file removed), OR
	// (b) it is now excluded (skipPathPrefixes/skipSubstrings added after the fact) —
	//     those paths will never appear in `seen` again and their findings should
	//     be reconciled (e.g. Spotlight journals after `mdutil -E /`).
	// Skip "git:" pseudo-entries — those aren't dashboard findings.
	for p := range prev {
		if strings.HasPrefix(p, "git:") {
			continue
		}
		if !seen[p] && underAnyRoot(p, roots) {
			deleted = append(deleted, p)
		}
	}
	return toScan, gitRepos, deleted, nil
}

func underAnyRoot(path string, roots []string) bool {
	for _, r := range roots {
		if r == "/" || (len(path) >= len(r) && path[:len(r)] == r) {
			return true
		}
	}
	return false
}

// Record upserts manifest rows for files that were just scanned. Call after a
// successful scan so the next sweep can skip unchanged files.
func (s *Store) Record(roots, excludes []string, rulesetVersion string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO manifest (path, size, ctime_ns, inode, last_scanned, ruleset_version)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET
			size=excluded.size, ctime_ns=excluded.ctime_ns, inode=excluded.inode,
			last_scanned=excluded.last_scanned, ruleset_version=excluded.ruleset_version
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	walkRegularFiles(roots, excludes,
		func(path string, key FileKey) {
			stmt.Exec(path, key.Size, key.CtimeNs, key.Inode, now, rulesetVersion)
		},
		func(repo string, key FileKey) {
			stmt.Exec("git:"+repo, key.Size, key.CtimeNs, key.Inode, now, rulesetVersion)
		},
	)
	stmt.Close()
	return tx.Commit()
}

// Forget removes deleted paths from the manifest.
func (s *Store) Forget(paths []string) {
	for _, p := range paths {
		s.db.Exec(`DELETE FROM manifest WHERE path=?`, p)
	}
}

// Clear wipes the manifest so the next sweep re-scans every file (forced full).
func (s *Store) Clear() error {
	_, err := s.db.Exec(`DELETE FROM manifest`)
	return err
}

// Checkpoint truncates the write-ahead log back to (near) zero. Record() commits
// ~900K upserts in one transaction, which passive autocheckpoint can never reset
// mid-transaction, so the -wal file grows unbounded (observed 474MB). Call this
// after Record() succeeds to keep the WAL bounded.
func (s *Store) Checkpoint() error {
	_, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}
