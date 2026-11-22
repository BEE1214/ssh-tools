package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"github.com/adamdvorsky/ssh-tools/internal/config"
)

// Interrupt safety of the verified saves (P7 R1). A save that has written its
// first byte is not finished until ssh has accepted the result: a SIGINT,
// SIGTERM or SIGHUP in between must not leave an unverified file behind (ssh
// would fail for every host, and sshm itself refuses to write on top of it).
// For exactly that stretch the save installs a handler (an interruptWindow):
// the signal cancels the ssh call that is running, the save takes the same
// rollback path as for a failed verification and returns an *InterruptedError.
// Outside the window nothing is installed, so the default behavior stays.
// SIGKILL cannot be handled and is out of scope.

// ErrInterrupted is what errors.Is finds in the *InterruptedError a save
// returns after a signal.
var ErrInterrupted = errors.New("interrupted")

// InterruptedError: a signal arrived while a save was verifying its write. The
// files were restored (Restored) or the restore failed (Err says why, Backup
// is the newest backup of File, "" when there is none).
type InterruptedError struct {
	// File is the file that was restored. For 'setup' and 'import' it is the
	// main file (the other file is restored as well).
	File     string
	Restored bool
	Backup   string
	Err      error
	// Signal is the signal received; the CLI exits with 128 plus its number.
	Signal syscall.Signal
}

func (e *InterruptedError) Error() string {
	if e.Restored {
		return fmt.Sprintf("interrupted: %s restored", e.File)
	}
	if e.Backup == "" {
		return fmt.Sprintf("interrupted: could not restore %s", e.File)
	}
	return fmt.Sprintf("interrupted: could not restore %s; backup: %s", e.File, e.Backup)
}

func (e *InterruptedError) Is(target error) bool { return target == ErrInterrupted }

func (e *InterruptedError) Unwrap() error { return e.Err }

// interruptWindow is the installed handler. Saves that overlap in one App
// (the TUI, tests) share one window; the last one to finish uninstalls it.
type interruptWindow struct {
	ctx     context.Context
	cancel  context.CancelFunc
	ch      chan os.Signal
	quit    chan struct{}
	done    chan struct{}
	sig     atomic.Int32 // the first signal received, 0 for none
	handled atomic.Bool  // an *InterruptedError was returned for it
	refs    int          // saves in the window, guarded by App.winMu
}

// openInterruptWindow installs the handler (signal.Notify) for the calling
// save, or joins the one that is installed, and makes the ssh calls of the App
// abort when a signal arrives. Close it with closeInterruptWindow, whatever
// happens.
func (a *App) openInterruptWindow() *interruptWindow {
	a.winMu.Lock()
	defer a.winMu.Unlock()
	if w := a.win; w != nil {
		w.refs++
		return w
	}
	w := &interruptWindow{
		ch:   make(chan os.Signal, 1),
		quit: make(chan struct{}),
		done: make(chan struct{}),
		refs: 1,
	}
	w.ctx, w.cancel = context.WithCancel(context.Background())
	signal.Notify(w.ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		defer close(w.done)
		for {
			select {
			case s := <-w.ch:
				w.record(s)
				w.cancel()
			case <-w.quit:
				return
			}
		}
	}()
	a.win = w
	return w
}

func (w *interruptWindow) record(s os.Signal) {
	if ss, ok := s.(syscall.Signal); ok {
		w.sig.CompareAndSwap(0, int32(ss))
	}
}

// fired reports whether a signal has arrived in the window.
func (w *interruptWindow) fired() bool { return w != nil && w.sig.Load() != 0 }

// signal returns the first signal received (0 for none).
func (w *interruptWindow) signal() syscall.Signal {
	if w == nil {
		return 0
	}
	return syscall.Signal(w.sig.Load())
}

// closeInterruptWindow leaves the window; the last save to leave uninstalls the
// handler. A signal that arrived but was not turned into an *InterruptedError
// (it came after the last check, the save went through) is delivered again with
// the default behavior restored, so it is not swallowed.
func (a *App) closeInterruptWindow(w *interruptWindow, err error) {
	if w == nil {
		return
	}
	if errors.Is(err, ErrInterrupted) {
		w.handled.Store(true)
	}
	a.winMu.Lock()
	defer a.winMu.Unlock()
	if w.refs--; w.refs > 0 {
		return
	}
	signal.Stop(w.ch)
	close(w.quit)
	<-w.done
	select { // a signal that reached the channel but not the goroutine
	case s := <-w.ch:
		w.record(s)
	default:
	}
	w.cancel()
	a.win = nil
	if sig := w.signal(); sig != 0 && !w.handled.Load() {
		if p, perr := os.FindProcess(os.Getpid()); perr == nil {
			p.Signal(sig)
		}
	}
}

// sshContext is the context of one ssh call: bounded by sshTimeout, and
// cancelled by a signal while an interrupt window is open.
func (a *App) sshContext() (context.Context, context.CancelFunc) {
	base := context.Background()
	a.winMu.Lock()
	if a.win != nil {
		base = a.win.ctx
	}
	a.winMu.Unlock()
	return context.WithTimeout(base, sshTimeout)
}

// interrupted builds the error of a save that was rolled back (rerr nil) or
// could not be rolled back (rerr says why) after a signal.
func (a *App) interrupted(w *interruptWindow, file string, rerr error) *InterruptedError {
	e := &InterruptedError{File: file, Restored: rerr == nil, Err: rerr, Signal: w.signal()}
	if rerr != nil {
		e.Backup, _ = a.newestBackup(file)
	}
	return e
}

// newestBackup returns the newest backup of file in sshm-backups.
func (a *App) newestBackup(file string) (string, bool) {
	base := filepath.Base(file)
	if target, err := config.WriteTarget(file); err == nil {
		base = filepath.Base(target) // BackupTo names backups after the resolved file
	}
	return config.NewestBackup(a.managedBackupDir(), base)
}

// backupHint is the tail the refusals of an already broken configuration get
// (P7 R2): " (newest backup of <file>: <path>)", or "" when sshm-backups holds
// no backup of file.
func (a *App) backupHint(file string) string {
	if p, ok := a.newestBackup(file); ok {
		return fmt.Sprintf(" (newest backup of %s: %s)", file, p)
	}
	return ""
}
