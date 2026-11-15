package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// Backup copies the config file to a timestamped .bak file in the same directory.
// Returns the path to the backup file.
func Backup(path string) (string, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read config: %w", err)
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)
	stamp := time.Now().Format("20060102-150405")
	bakPath := filepath.Join(dir, base+".bak."+stamp)

	if err := os.WriteFile(bakPath, src, 0o600); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}

	return bakPath, nil
}

// MaxBackups is how many backups BackupTo keeps per file name in a backup
// directory. Every managed-file save makes one, so without a limit the
// directory grows forever; 20 covers a long editing session and is small
// enough to look through by hand. The oldest ones beyond it are deleted.
const MaxBackups = 20

// backupStamp is the timestamp layout of BackupTo names. Fixed width, so the
// names sort by age.
const backupStamp = "20060102-150405.000000"

// BackupTo copies the file at path (symlinks are followed) into dir as
// "<base>.<timestamp>" with mode 0600, creating dir with mode 0700 if needed.
// A name that is already taken (two saves in the same instant) gets a
// numeric suffix instead of overwriting the earlier backup. Returns the
// backup's path. The file must exist. Afterwards only the newest MaxBackups
// backups of that base name are kept (pruning errors are ignored: the backup
// itself succeeded).
func BackupTo(path, dir string) (string, error) {
	bak, err := backupTo(path, dir)
	if err == nil {
		PruneBackups(dir, filepath.Base(path), MaxBackups)
	}
	return bak, err
}

// PruneBackups deletes all but the newest keep backups that BackupTo made
// for the file name base in dir, and returns the paths it removed. Only names
// of the exact form "<base>.<timestamp>[-n]" are touched, so "config.old.x"
// is never counted as a backup of "config".
func PruneBackups(dir, base string, keep int) []string {
	ents, err := os.ReadDir(dir)
	if err != nil || keep < 0 {
		return nil
	}
	type bak struct {
		name, stamp string
		n           int
	}
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(base) + `\.(\d{8}-\d{6}\.\d{6})(?:-(\d+))?$`)
	var baks []bak
	for _, e := range ents {
		m := re.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		n, _ := strconv.Atoi(m[2]) // "" (no collision suffix) is 0
		baks = append(baks, bak{e.Name(), m[1], n})
	}
	sort.Slice(baks, func(i, j int) bool { // newest first
		if baks[i].stamp != baks[j].stamp {
			return baks[i].stamp > baks[j].stamp
		}
		return baks[i].n > baks[j].n
	})
	var removed []string
	for i := keep; i < len(baks); i++ {
		p := filepath.Join(dir, baks[i].name)
		if os.Remove(p) == nil {
			removed = append(removed, p)
		}
	}
	return removed
}

func backupTo(path, dir string) (string, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s for backup: %w", path, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
	}

	stem := filepath.Join(dir, filepath.Base(path)+"."+time.Now().Format(backupStamp))
	for n := 0; n < 1000; n++ {
		bak := stem
		if n > 0 {
			bak = fmt.Sprintf("%s-%d", stem, n)
		}
		f, err := os.OpenFile(bak, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("write backup: %w", err)
		}
		_, werr := f.Write(src)
		if werr == nil {
			werr = f.Sync()
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			os.Remove(bak)
			return "", fmt.Errorf("write backup: %w", werr)
		}
		return bak, nil
	}
	return "", fmt.Errorf("write backup: no free file name in %s", dir)
}
