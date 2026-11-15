package app

import (
	"fmt"
	"sort"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// AddHost adds a new host to the config file.
// Returns an error if a host with the same name already exists.
func (a *App) AddHost(h domain.Host) error {
	if v, err := a.activeView(); err != nil {
		return err
	} else if v != nil {
		return a.addHostManaged(v, h)
	}
	// The name must not exist in ANY loaded file, not only the main one.
	if err := a.ensureInMain(h.Name); err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}

	if findHostIndex(cfg.Hosts, h.Name) != -1 {
		return fmt.Errorf("host %q already exists", h.Name)
	}

	// Set group if not already set.
	if h.Group == "" {
		h.Group = domain.GroupFor(h.Name)
	}
	h.Source = domain.SourceManual

	cfg.Hosts = append(cfg.Hosts, h)
	return a.save(cfg)
}

// EditHost applies changes to an existing host.
// changes is a map of field name to new value. Known field names:
// hostname, user, port, identityfile, proxyjump, proxycommand,
// forwardagent, forwardx11, stricthostkeychecking, loglevel
func (a *App) EditHost(name string, changes map[string]string) error {
	if v, err := a.activeView(); err != nil {
		return err
	} else if v != nil {
		return a.editHostManaged(v, name, changes)
	}
	if err := a.ensureInMain(name); err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}

	idx := findHostIndex(cfg.Hosts, name)
	if idx == -1 {
		return fmt.Errorf("host %q not found", name)
	}

	h := &cfg.Hosts[idx]
	if err := ensureEditable(*h); err != nil {
		return err
	}
	if h.Source == domain.SourceDevPod {
		return fmt.Errorf("host %q is managed by DevPod — edit via DevPod instead", name)
	}

	for key, value := range changes {
		applyChange(h, key, value)
	}

	return a.save(cfg)
}

// DeleteHost removes a host from the config file.
func (a *App) DeleteHost(name string) error {
	if v, err := a.activeView(); err != nil {
		return err
	} else if v != nil {
		return a.deleteHostManaged(v, name)
	}
	if err := a.ensureInMain(name); err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}

	idx := findHostIndex(cfg.Hosts, name)
	if idx == -1 {
		return fmt.Errorf("host %q not found", name)
	}

	if cfg.Hosts[idx].Source == domain.SourceDevPod {
		return fmt.Errorf("host %q is managed by DevPod — remove via DevPod instead", name)
	}

	cfg.Hosts = append(cfg.Hosts[:idx], cfg.Hosts[idx+1:]...)
	return a.save(cfg)
}

// DuplicateHost creates a copy of an existing host with a new name.
func (a *App) DuplicateHost(srcName, newName string) error {
	if v, err := a.activeView(); err != nil {
		return err
	} else if v != nil {
		return a.duplicateHostManaged(v, srcName, newName)
	}
	if err := a.ensureInMain(srcName); err != nil {
		return err
	}
	if err := a.ensureInMain(newName); err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}

	idx := findHostIndex(cfg.Hosts, srcName)
	if idx == -1 {
		return fmt.Errorf("source host %q not found", srcName)
	}
	if err := ensureEditable(cfg.Hosts[idx]); err != nil {
		return err
	}

	if findHostIndex(cfg.Hosts, newName) != -1 {
		return fmt.Errorf("host %q already exists", newName)
	}

	dup := cfg.Hosts[idx]
	dup.Name = newName
	dup.Patterns = nil // derived from the old Name, see domain.Host.Patterns
	dup.Group = domain.GroupFor(newName)
	dup.Source = domain.SourceManual
	dup.LineStart = 0
	dup.LineEnd = 0

	cfg.Hosts = append(cfg.Hosts, dup)
	return a.save(cfg)
}

// ensureEditable rejects modifications of a host that is commented out of the
// config (disabled group). The writer re-emits a disabled host's verbatim
// block, so any field change would be silently lost.
func ensureEditable(h domain.Host) error {
	if isHostDisabled(h) {
		return fmt.Errorf(
			"host %q is in disabled group %q — run 'sshm groups enable %s' first",
			h.Name, h.Group, h.Group)
	}
	return nil
}

// applyChange sets a field on the host based on a key name (case-insensitive).
func applyChange(h *domain.Host, key, value string) {
	switch strings.ToLower(key) {
	case "hostname":
		h.HostName = value
	case "user":
		h.User = value
	case "port":
		h.Port = value
	// An edit sets THE identity (certificate) file of the block: every
	// existing line is replaced by the one new value, and an empty value
	// removes them all. Keeping the other lines would turn "IdentityFile a /
	// IdentityFile b" plus identityfile=new into "new, b" (the edit left
	// exactly one line before the parser kept every value).
	case "identityfile":
		h.IdentityFile, h.IdentityFiles = singleFile(value)
	case "certificatefile":
		h.CertificateFile, h.CertificateFiles = singleFile(value)
	case "proxyjump":
		h.ProxyJump = value
	case "proxycommand":
		h.ProxyCommand = value
	case "forwardagent":
		h.ForwardAgent = value
	case "forwardx11":
		h.ForwardX11 = value
	case "stricthostkeychecking":
		h.StrictHostKeyChecking = value
	case "loglevel":
		h.LogLevel = value
	// The remaining modeled options: without these cases an edit would land
	// in Extra NEXT TO the field the parser filled, and the writer would
	// emit both lines (ssh keeps the first, i.e. the old value).
	case "hostkeyalgorithms":
		h.HostKeyAlgorithms = value
	case "kexalgorithms":
		h.KexAlgorithms = value
	case "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes":
		h.PubkeyAcceptedAlgorithms = value
	case "ciphers":
		h.Ciphers = value
	case "macs":
		h.MACs = value
	default:
		setExtra(h, key, value)
	}
}

// singleFile returns the Host fields for an IdentityFile / CertificateFile
// option that has exactly one value (or none when value is empty): the
// singular field and the full list (see domain.Host.IdentityFiles).
func singleFile(value string) (first string, all []string) {
	if value == "" {
		return "", nil
	}
	return value, []string{value}
}

// setExtra stores an unmodeled option. ssh keywords are case-insensitive, so
// an existing entry is matched ignoring case and keeps its spelling; a second
// entry that differs only in case ("ServerAliveInterval" next to
// "serveraliveinterval") is never created, and stale ones are merged away.
func setExtra(h *domain.Host, key, value string) {
	if h.Extra == nil {
		h.Extra = make(map[string]string)
	}
	var same []string
	for k := range h.Extra {
		if strings.EqualFold(k, key) {
			same = append(same, k)
		}
	}
	if len(same) == 0 {
		h.Extra[key] = value
		return
	}
	sort.Strings(same) // deterministic survivor when stale duplicates exist
	for _, k := range same[1:] {
		delete(h.Extra, k)
	}
	h.Extra[same[0]] = value
}
