// Package manifest implements the SQLite-backed file manifest and the safe,
// incremental filesystem walk that drives Sandwalk's daily sweep.
package manifest

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// skipDirNames are directory basenames never worth scanning (noise or hazards).
var skipDirNames = map[string]bool{
	"System": true, "bin": true, "sbin": true, "dev": true,
	".Spotlight-V100": true, ".fseventsd": true, ".DocumentRevisions-V100": true,
	".TemporaryItems": true, ".Trashes": true, ".vol": true,
	"Caches": true, "Developer": true, "Volumes": true, "CoreSimulator": true,
	"Xcode": true, "DerivedData": true, "Archives": true, "Applications": true,
	"node_modules": true, "__pycache__": true, ".mypy_cache": true, ".pytest_cache": true,
	"dist": true, "build": true, "target": true, ".next": true, ".nuxt": true, ".cache": true,
	"site-packages": true, "venv": true, ".venv": true, ".npm": true, "_cacache": true,
	"Photos Library.photoslibrary": true, "Mail": true,
	"sandwalk": true, "JumpCloud Password Manager": true,
	// Language/build caches — high file counts, no real credentials.
	".gradle": true, ".m2": true, ".cargo": true, ".rustup": true, ".pub-cache": true,
	".cocoapods": true, "Pods": true, ".terraform": true, ".claude-odyssey": true,
	".pyenv": true, ".rbenv": true, ".nvm": true, "Logs": true,
}

// skipPathPrefixes are absolute path prefixes always skipped. /System/Volumes is
// excluded to avoid double-walking firmlinked user data (we reach it via / paths).
var skipPathPrefixes = []string{
	"/System/Volumes", "/private/var/db", "/private/var/folders",
	"/private/var/vm", "/private/var/run", "/private/tmp", "/tmp",
	"/net", "/home", "/dev",
	"/opt/sandwalk", "/opt/homebrew/Cellar", "/opt/homebrew/lib",
	// Spotlight internal index — binary journal files, not readable credentials.
	// Finding a secret here means Spotlight indexed a file that had it; the fix
	// is to rotate the secret and run `sudo mdutil -E /`, not to flag the journal.
	"/Library/Metadata/CoreSpotlight",
}

// skipExtensions are binary/media files never worth reading.
var skipExtensions = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true, ".ico": true,
	".webp": true, ".mp4": true, ".mov": true, ".avi": true, ".mkv": true, ".mp3": true,
	".wav": true, ".zip": true, ".tar": true, ".gz": true, ".bz2": true, ".7z": true,
	".rar": true, ".dylib": true, ".so": true, ".app": true, ".dmg": true,
	".pdf": true, ".docx": true, ".xlsx": true, ".pptx": true,
	".sqlite": true, ".sqlite3": true, ".class": true, ".jar": true, ".wasm": true,
}

const maxFileBytes = 2 * 1024 * 1024 // skip files larger than 2MB

// FileKey is the change-detection tuple for a regular file. ctime is
// kernel-controlled (cannot be forged with `touch -m`), so it's the primary
// tamper signal; inode catches file swaps.
type FileKey struct {
	Size    int64
	CtimeNs int64
	Inode   uint64
}

// Watchable reports whether a path changed in real time is worth scanning. It
// filters obvious noise (excluded prefixes, skip dirs, binary extensions);
// Kingfisher decides whether the file actually contains a secret.
func Watchable(path string, extraExcludes []string) bool {
	if excluded(path, extraExcludes) {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if skipDirNames[part] {
			return false
		}
	}
	for _, sub := range skipSubstrings {
		if strings.Contains(path, sub) {
			return false
		}
	}
	return !skipExtensions[strings.ToLower(filepath.Ext(path))]
}

// skipSubstrings match anywhere in a path — language module caches that aren't
// anchored to a fixed prefix.
var skipSubstrings = []string{
	"/go/pkg/",
	"/Library/Caches/",
	"/Library/Logs/",
	// Slack IndexedDB blob cache — fires hundreds of watcher events per hour,
	// always 0 findings. Binary blob files, not human-readable credentials.
	"/Slack/IndexedDB/",
	// Other Electron/browser app data stores with same characteristics.
	"/Application Support/Slack/",
	"/Application Support/Google/Chrome/",
	"/Application Support/Microsoft Edge/",
	"/Application Support/Firefox/",
	"/Application Support/Code/User/globalStorage/",
}

func excluded(path string, extraExcludes []string) bool {
	for _, p := range skipPathPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	for _, s := range skipSubstrings {
		if strings.Contains(path, s) {
			return true
		}
	}
	for _, p := range extraExcludes {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// gitStateKey returns a change-detection key for a repo's history: the reflog
// (.git/logs/HEAD) advances on every commit; fall back to the .git dir itself.
func gitStateKey(gitDir string) FileKey {
	for _, p := range []string{filepath.Join(gitDir, "logs", "HEAD"), gitDir} {
		if info, err := os.Lstat(p); err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				return FileKey{Size: info.Size(), CtimeNs: st.Ctimespec.Sec*1e9 + st.Ctimespec.Nsec, Inode: st.Ino}
			}
		}
	}
	return FileKey{}
}

// walkRegularFiles traverses roots, invoking onFile for every readable regular
// file and onGitRoot for every git repository root discovered (so the caller can
// scan its history). onGitRoot may be nil.
func walkRegularFiles(roots, extraExcludes []string, fn func(path string, key FileKey), onGitRoot func(repo string, key FileKey)) {
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// Permission denied / transient error — skip this entry, keep going.
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				base := filepath.Base(path)
				if base == ".git" {
					// Parent is a git repo root — record it for history scanning,
					// then skip .git internals (compressed blobs aren't useful as files).
					if onGitRoot != nil {
						repo := filepath.Dir(path)
						if !excluded(repo, extraExcludes) {
							onGitRoot(repo, gitStateKey(path))
						}
					}
					return filepath.SkipDir
				}
				if skipDirNames[base] || excluded(path, extraExcludes) {
					return filepath.SkipDir
				}
				return nil
			}
			// Only regular files. d.Type() reflects lstat — symlinks/FIFOs/
			// sockets/devices are NOT regular and are skipped without opening.
			if !d.Type().IsRegular() {
				return nil
			}
			if skipExtensions[strings.ToLower(filepath.Ext(path))] {
				return nil
			}
			if excluded(path, extraExcludes) {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil || info.Size() > maxFileBytes {
				return nil
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			fn(path, FileKey{
				Size:    info.Size(),
				CtimeNs: st.Ctimespec.Sec*1e9 + st.Ctimespec.Nsec,
				Inode:   st.Ino,
			})
			return nil
		})
	}
}
