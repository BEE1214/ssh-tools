package config

import (
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// genDoc builds a random managed-file-like document: a preamble, then blocks
// of every kind (plain hosts in assorted styles, multi-pattern, wildcard,
// Match, a disabled region), with comments, blank lines, repeated keys,
// Key=value forms, tabs and inline comments sprinkled in. Plain host names are
// h0, h1, ...; they are returned in file order.
func genDoc(r *rand.Rand) (text string, plain []string) {
	var out []string
	add := func(l ...string) { out = append(out, l...) }
	pick := func(xs ...string) string { return xs[r.Intn(len(xs))] }

	for i, n := 0, r.Intn(4); i < n; i++ {
		add(pick("# preamble", "Include /nonexistent/x.conf", "ServerAliveInterval 20", "", "# sshm managed"))
	}
	if r.Intn(2) == 0 {
		add("")
	}

	nBlocks := 1 + r.Intn(6)
	for b := 0; b < nBlocks; b++ {
		if r.Intn(3) == 0 { // comment attached above (or loose, after a blank)
			add(fmt.Sprintf("# about block %d", b))
			if r.Intn(2) == 0 {
				add("")
			}
		}
		indent := pick("  ", "\t", "    ")
		opt := func() string {
			switch r.Intn(14) {
			case 0: // an Include inside the block (conditional in ssh)
				return indent + pick("Include", "include") + " /nonexistent/in-block.conf"
			case 1: // rest-of-line option: the "#" is part of the value
				return indent + "KnownHostsCommand /bin/echo %H # not a comment"
			}
			key := pick("HostName", "User", "Port", "IdentityFile", "IdentityFile", "LocalForward",
				"ForwardAgent", "ServerAliveInterval", "ProxyJump", "CertificateFile", "user", "hostname",
				"HOSTNAME", "USER", "identityfile")
			var sep string
			switch r.Intn(6) {
			case 0:
				sep = "="
			case 1:
				sep = " = "
			case 2:
				sep = "\t"
			default:
				sep = " "
			}
			val := pick("10.0.0.1", "alice", "2222", "~/.ssh/k1", "~/.ssh/k2", "8080 localhost:80", "yes", "30", `"quoted value"`)
			l := indent + key + sep + val
			switch r.Intn(6) {
			case 0:
				l += "  # note"
			case 1:
				l += "\t# tab note"
			}
			return l
		}
		// hostLine writes a Host line for one pattern in a random spelling:
		// keyword casing, separator, quotes, inline comment.
		hostLine := func(name string) string {
			l := pick("Host ", "host ", "HOST ", "Host=", "Host\t", "Host = ", "hOsT  ")
			l += pick(name, name, name, `"`+name+`"`, "'"+name+"'")
			return l + pick("", "", "", " # note", "\t# tab note", " #x")
		}
		body := func() {
			for i, n := 0, r.Intn(6); i < n; i++ {
				add(opt())
				switch r.Intn(6) {
				case 0:
					add(indent + "# inner comment")
				case 1:
					add("")
				}
			}
			if r.Intn(4) == 0 {
				add(indent + "# trailing")
			}
		}
		switch k := r.Intn(12); {
		case k == 0:
			add(fmt.Sprintf(pick("Host multi%da multi%db", "Host \"multi%da\"\tmulti%db # two", "HOST=multi%da 'multi%db'"), b, b))
			body()
		case k == 1:
			add(fmt.Sprintf(pick("Host wild%d-*", "host \"wild%d-*\" # w", "Host wild%d-? !wild0-x"), b))
			body()
		case k == 2:
			add(fmt.Sprintf(pick("Match host m%d", "match host m%d", "Match\thost=\"m%d\" user x # c", "MATCH all # m%d"), b))
			body()
		case k == 3:
			add(fmt.Sprintf("# sshm disabled group=gen%d start", b))
			add("# " + hostLine(fmt.Sprintf("dis%d", b)))
			add("#   HostName 10.0.0.9")
			if r.Intn(3) == 0 { // a second host in the same region
				add("#", "# "+hostLine(fmt.Sprintf("dis%db", b)), "# \tUser u")
			}
			add(fmt.Sprintf("# sshm disabled group=gen%d end", b))
		case k == 4:
			// A Host line whose arguments are only a comment: a block that
			// matches nothing, for the Doc and the parser alike.
			add("Host # no pattern at all")
			body()
		default:
			name := fmt.Sprintf("h%d", len(plain))
			plain = append(plain, name)
			add(hostLine(name))
			body()
		}
		// 0-2 blank lines after the block: 0 means the next block (or a
		// disabled region, or a comment) follows with no blank line between.
		for i, n := 0, r.Intn(3); i < n; i++ {
			add("")
		}
	}
	text = strings.Join(out, "\n")
	if r.Intn(6) != 0 { // sometimes the final newline is missing
		text += "\n"
	}
	return text, plain
}

func rawOf(d *Doc, bs []Block) [][]string {
	var out [][]string
	for _, b := range bs {
		out = append(out, append([]string(nil), d.Raw(b)...))
	}
	return out
}

// lineDiff trims the common prefix and suffix of a and b and returns what is
// left of each: the lines removed from a and the lines added in b.
func lineDiff(a, b []string) (removed, added []string) {
	p := 0
	for p < len(a) && p < len(b) && a[p] == b[p] {
		p++
	}
	s := 0
	for s < len(a)-p && s < len(b)-p && a[len(a)-1-s] == b[len(b)-1-s] {
		s++
	}
	return a[p : len(a)-s], b[p : len(b)-s]
}

func lineKey(l string) string {
	if o, ok := parseOptLine(l); ok {
		return o.key
	}
	return ""
}

// optionValues returns the values of every `key` line in lines.
func optionValues(lines []string, key string) []string {
	var vs []string
	for _, l := range lines {
		if o, ok := parseOptLine(l); ok && sameKey(o.key, key) {
			vs = append(vs, o.value)
		}
	}
	return vs
}

// TestDocProperty applies random sequences of operations to random documents
// and checks, for every step: a failing operation changes nothing; every
// block that is not the target is byte-identical afterwards (same raw lines,
// same order); everything outside the target's span is byte-identical; and
// the target changed only on the intended line(s).
//
// Differential part (review M5): at the start and after EVERY operation the
// legacy parser must read the document the way the Doc does: the same host
// names in the same order, the same disabled flags, the same disabled group
// (docVsParse).
//
// Seeds: the fixed seed is the regression case. A second run uses a fresh
// seed every time (or SSHM_PROP_SEED=<n> to reproduce); the seed is logged
// and repeated when the run fails.
func TestDocProperty(t *testing.T) {
	// The two runs share nothing and spend most of their time waiting for
	// ssh (the legacy comparison), so they run side by side.
	t.Run("fixed", func(t *testing.T) {
		t.Parallel()
		runDocProperty(t, propFixedSeed, true)
	})
	t.Run("random", func(t *testing.T) {
		t.Parallel()
		seed := time.Now().UnixNano()
		if s := os.Getenv("SSHM_PROP_SEED"); s != "" {
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				t.Fatalf("SSHM_PROP_SEED=%q: %v", s, err)
			}
			seed = n
		}
		runDocProperty(t, seed, false)
	})
}

// propFixedSeed is the regression seed of TestDocProperty.
const propFixedSeed = 20261114

// hostRec is what docVsParse compares, one record per host: its pattern LIST
// (element by element: one pattern "a b" is not the two patterns a and b),
// whether it is disabled, and the group of the disabled region.
type hostRec struct {
	names    []string
	disabled bool
	group    string
}

func (r hostRec) String() string {
	return fmt.Sprintf("{%q disabled=%v group=%q}", r.names, r.disabled, r.group)
}

// docRecs lists the hosts as the Doc reads them: an enabled block is one
// record with all its patterns (Block.Names), a disabled region is one record
// per name inside it. Match blocks are not hosts.
func docRecs(d *Doc) []hostRec {
	var out []hostRec
	for _, b := range d.Blocks() {
		switch {
		case b.Match:
		case b.Disabled:
			for _, n := range b.Names {
				out = append(out, hostRec{[]string{n}, true, b.Group})
			}
		default:
			out = append(out, hostRec{append([]string{}, b.Names...), false, ""})
		}
	}
	return out
}

// parseRecs is docRecs for the parser. The names to compare are Host.Patterns
// (Host.Name joins them), which Parse always sets.
func parseRecs(cfg *ConfigFile) ([]hostRec, error) {
	var out []hostRec
	for _, h := range cfg.Hosts {
		if h.Patterns == nil {
			return nil, fmt.Errorf("Parse left Patterns nil for host %q", h.Name)
		}
		if h.Disabled {
			for _, n := range h.Patterns {
				out = append(out, hostRec{[]string{n}, true, h.Group})
			}
		} else {
			out = append(out, hostRec{append([]string{}, h.Patterns...), false, ""})
		}
	}
	return out, nil
}

// docVsParse compares what the Doc and the legacy parser make of the same
// bytes (docRecs against parseRecs).
func docVsParse(d *Doc) error {
	cfg, err := Parse(d.Bytes())
	if err != nil {
		return fmt.Errorf("Parse fails on a document the Doc accepts: %v", err)
	}
	fromDoc := docRecs(d)
	fromParse, err := parseRecs(cfg)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(fromDoc, fromParse) {
		return fmt.Errorf("Doc and Parse disagree on the hosts (patterns, disabled, group):\n  Doc:   %v\n  Parse: %v", fromDoc, fromParse)
	}
	return nil
}

// The comparison is on pattern lists: `Host "a b"` (one pattern) and
// `Host a b` (two) are different hosts, whichever side reads which.
func TestDocVsParseComparesPatternLists(t *testing.T) {
	one := docRecs(ParseDoc([]byte("Host \"a b\"\n  User u\n")))
	cfg, err := Parse([]byte("Host a b\n  User u\n"))
	if err != nil {
		t.Fatal(err)
	}
	two, err := parseRecs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || len(one[0].names) != 1 || len(two) != 1 || len(two[0].names) != 2 {
		t.Fatalf("fixture: Doc %v, Parse %v", one, two)
	}
	if reflect.DeepEqual(one, two) {
		t.Errorf("one pattern %v and two patterns %v compare equal", one, two)
	}
	// And the same line read by both sides agrees.
	for _, text := range []string{"Host \"a b\"\n", "Host a b\n", "Host # none\n", "Host a\\ b c\n"} {
		if err := docVsParse(ParseDoc([]byte(text))); err != nil {
			t.Errorf("%q: %v", text, err)
		}
	}
}

func runDocProperty(t *testing.T, seed int64, checkCounts bool) {
	t.Logf("seed %d", seed)
	defer func() {
		if t.Failed() {
			t.Logf("FAILED with seed %d: reproduce with SSHM_PROP_SEED=%d go test ./internal/config -run 'TestDocProperty/random'", seed, seed)
		}
	}()
	r := rand.New(rand.NewSource(seed))
	keys := []string{"HostName", "User", "Port", "IdentityFile", "CertificateFile", "LocalForward", "ForwardAgent", "ProxyJump", "ServerAliveInterval"}
	listKeys := []string{"IdentityFile", "LocalForward", "CertificateFile", "RemoteForward"}
	vals := []string{"v1", "10.9.8.7", "~/.ssh/new", "9000 h:9", "no"}
	var counts = map[string]int{}
	for iter := 0; iter < 200; iter++ {
		text, plain := genDoc(r)
		d := ParseDoc([]byte(text))
		if want := strings.TrimSuffix(text, "\n") + "\n"; string(d.Bytes()) != want {
			t.Fatalf("iter %d: Bytes() != input (plus a final newline when it was missing)", iter)
		}
		if err := docVsParse(d); err != nil {
			t.Fatalf("iter %d, generated document:\n%s\n%v", iter, text, err)
		}

		for step := 0; step < 8; step++ {
			if step > 0 {
				if err := docVsParse(d); err != nil {
					t.Fatalf("iter %d before step %d:\n%s\n%v", iter, step, strings.Join(d.Lines, "\n"), err)
				}
			}
			beforeLines := append([]string(nil), d.Lines...)
			before := ParseDoc([]byte(string(d.Bytes())))
			bblocks := before.Blocks()

			// Pick a target: usually a known plain host, sometimes junk.
			target := "nope"
			if len(plain) > 0 && r.Intn(8) != 0 {
				target = plain[r.Intn(len(plain))]
			}
			tIdx := -1
			for i, b := range bblocks {
				if !b.Match && !b.Disabled && len(b.Names) == 1 && b.Names[0] == target {
					tIdx = i
				}
			}
			// Several blocks with the same name cannot happen in the
			// generator except through DuplicateBlock/AppendBlock, which
			// refuse existing names.

			op := r.Intn(8)
			key := keys[r.Intn(len(keys))]
			lkey := listKeys[r.Intn(len(listKeys))]
			val := vals[r.Intn(len(vals))]
			if op == 3 && tIdx >= 0 && r.Intn(4) != 0 { // mostly remove a value that exists
				raw := rawOf(before, bblocks)[tIdx]
				var present []string
				for _, k := range listKeys {
					if len(optionValues(raw, k)) > 0 {
						present = append(present, k)
					}
				}
				if len(present) > 0 {
					lkey = present[r.Intn(len(present))]
					have := optionValues(raw, lkey)
					val = have[r.Intn(len(have))]
				}
			}
			newName := fmt.Sprintf("n%d_%d", iter, step)
			var err error
			desc := ""
			switch op {
			case 0:
				desc = fmt.Sprintf("SetOption(%s,%s,%s)", target, key, val)
				err = d.SetOption(target, key, val)
			case 1:
				desc = fmt.Sprintf("UnsetOption(%s,%s)", target, key)
				err = d.UnsetOption(target, key)
			case 2:
				desc = fmt.Sprintf("AddOptionValue(%s,%s,%s)", target, lkey, val)
				err = d.AddOptionValue(target, lkey, val)
			case 3:
				desc = fmt.Sprintf("RemoveOptionValue(%s,%s,%s)", target, lkey, val)
				err = d.RemoveOptionValue(target, lkey, val)
			case 4:
				desc = fmt.Sprintf("AppendBlock(%s)", newName)
				err = d.AppendBlock(domain.Host{Name: newName, HostName: "10.1.1.1", Port: "22", IdentityFiles: []string{"a", "b"}})
			case 5:
				desc = fmt.Sprintf("DeleteBlock(%s)", target)
				err = d.DeleteBlock(target)
			case 6:
				desc = fmt.Sprintf("DuplicateBlock(%s,%s)", target, newName)
				err = d.DuplicateBlock(target, newName)
			case 7:
				// Disable + Enable round trip on a random subset.
				var names []string
				for _, p := range plain {
					if r.Intn(2) == 0 {
						names = append(names, p)
					}
				}
				desc = fmt.Sprintf("Disable/Enable(%v)", names)
				snapshot := string(d.Bytes())
				if derr := d.DisableBlocks(names, "propgrp"); derr != nil {
					if string(d.Bytes()) != snapshot {
						t.Fatalf("iter %d step %d %s: failed DisableBlocks changed the doc", iter, step, desc)
					}
					counts["disable-refused"]++ // e.g. empty subset
					continue
				}
				// The parser must see the disabled state exactly like the Doc.
				if err := docVsParse(d); err != nil {
					t.Fatalf("iter %d step %d %s, after DisableBlocks:\n%s\n%v", iter, step, desc, strings.Join(d.Lines, "\n"), err)
				}
				// Untargeted blocks identical, targeted ones now disabled regions.
				mid := d.Blocks()
				disabledSeen := 0
				for _, b := range mid {
					if b.Disabled && b.Group == "propgrp" {
						disabledSeen++
					}
				}
				if disabledSeen != len(names) {
					t.Fatalf("iter %d step %d %s: %d disabled regions for %d names", iter, step, desc, disabledSeen, len(names))
				}
				if got := untargetedRaws(d, mid, func(b Block) bool { return b.Disabled && b.Group == "propgrp" }); !reflect.DeepEqual(got, untargetedRaws(before, bblocks, func(b Block) bool { return !b.Disabled && !b.Match && len(b.Names) == 1 && contains(names, b.Names[0]) })) {
					t.Fatalf("iter %d step %d %s: untargeted blocks changed\n%s", iter, step, desc, text)
				}
				if err := d.EnableGroup("propgrp"); err != nil {
					t.Fatalf("iter %d step %d %s: enable: %v", iter, step, desc, err)
				}
				if string(d.Bytes()) != snapshot {
					t.Fatalf("iter %d step %d %s: Disable->Enable is not identity\nbefore %q\nafter  %q", iter, step, desc, snapshot, d.Bytes())
				}
				counts["disable-enable"]++
				continue
			}

			if err != nil {
				if !reflect.DeepEqual(d.Lines, beforeLines) {
					t.Fatalf("iter %d step %d %s: error %v but doc changed", iter, step, desc, err)
				}
				counts[strings.SplitN(desc, "(", 2)[0]+"-err"]++
				continue
			}
			counts[strings.SplitN(desc, "(", 2)[0]]++
			ctx := fmt.Sprintf("iter %d step %d %s\nbefore:\n%s\nafter:\n%s", iter, step, desc, strings.Join(beforeLines, "\n"), strings.Join(d.Lines, "\n"))

			after := d.Blocks()
			ablocks := rawOf(d, after)
			bblockRaws := rawOf(before, bblocks)

			switch op {
			case 0, 1, 2, 3: // in-block edits
				if tIdx < 0 {
					t.Fatalf("%s: op succeeded on a non-plain target\n%s", desc, ctx)
				}
				tb := bblocks[tIdx]
				// Everything outside the target span is byte-identical.
				tail := len(beforeLines) - tb.End
				if !reflect.DeepEqual(d.Lines[:tb.Start], beforeLines[:tb.Start]) ||
					!reflect.DeepEqual(d.Lines[len(d.Lines)-tail:], beforeLines[tb.End:]) {
					t.Fatalf("lines outside the target block changed\n%s", ctx)
				}
				if len(after) != len(bblocks) {
					t.Fatalf("block count changed\n%s", ctx)
				}
				for i := range bblocks {
					if i == tIdx || reflect.DeepEqual(ablocks[i], bblockRaws[i]) {
						continue
					}
					// Known, byte-neutral exception: when Unset/Remove deletes the
					// target's LAST option line in a layout without a blank line
					// before the next block, comment lines that followed it now
					// sit directly above the next block and are read as ITS
					// leading comments. No byte changed (checked above); only
					// the comment-line ownership at the block's edge moved.
					if i == tIdx+1 && (op == 1 || op == 3) &&
						reflect.DeepEqual(trimEdgeComments(ablocks[i]), trimEdgeComments(bblockRaws[i])) {
						continue
					}
					t.Fatalf("untargeted block %d changed\n%s", i, ctx)
				}
				// Unset / Remove: the block is exactly the old block minus the
				// matching lines (comments and every other line stay).
				// (Compared on the whole document, which is immune to the
				// comment-ownership drift described above.)
				filter := func(drop func(optLine) bool) []string {
					var keep []string
					for i, l := range beforeLines {
						if o, ok := parseOptLine(l); ok && i > tb.HostLine && i < tb.End && drop(o) {
							continue
						}
						keep = append(keep, l)
					}
					return keep
				}
				if op == 1 {
					want := filter(func(o optLine) bool { return sameKey(o.key, key) })
					if !reflect.DeepEqual(d.Lines, want) {
						t.Fatalf("UnsetOption: doc is not old doc minus the %s lines of the block\n%s", key, ctx)
					}
				}
				if op == 3 {
					want := filter(func(o optLine) bool {
						return sameKey(o.key, lkey) && strings.Join(strings.Fields(o.value), " ") == strings.Join(strings.Fields(val), " ")
					})
					if !reflect.DeepEqual(d.Lines, want) {
						t.Fatalf("RemoveOptionValue: doc is not old doc minus the matching lines of the block\n%s", ctx)
					}
				}
				removed, added := lineDiff(bblockRaws[tIdx], ablocks[tIdx])
				if op == 0 || op == 2 {
					want := key
					if op == 2 {
						want = lkey
					}
					for _, l := range append(append([]string(nil), removed...), added...) {
						if !sameKey(lineKey(l), want) {
							t.Fatalf("a line of another option changed: %q\n%s", l, ctx)
						}
					}
				}
				switch op {
				case 0:
					if got := optionValues(ablocks[tIdx], key); len(got) != 1 || got[0] != val {
						t.Fatalf("SetOption result values %v, want [%s]\n%s", got, val, ctx)
					}
					switch {
					case len(removed) == 1 && len(added) == 1: // in place: only the value differs
						o1, _ := parseOptLine(removed[0])
						o2, _ := parseOptLine(added[0])
						o1.value, o2.value = "", ""
						if o1 != o2 {
							t.Fatalf("patched line lost indent/key/separator/comment: %q -> %q\n%s", removed[0], added[0], ctx)
						}
					case len(removed) == 0 && len(added) <= 1: // inserted, or value unchanged
					default:
						t.Fatalf("SetOption diff removed=%q added=%q\n%s", removed, added, ctx)
					}
				case 1:
					if len(optionValues(ablocks[tIdx], key)) != 0 {
						t.Fatalf("UnsetOption left %s lines\n%s", key, ctx)
					}
				case 2:
					if len(removed) != 0 || len(added) > 1 || !contains(normAll(optionValues(ablocks[tIdx], lkey)), strings.Join(strings.Fields(val), " ")) {
						t.Fatalf("AddOptionValue diff removed=%q added=%q\n%s", removed, added, ctx)
					}
				case 3:
					if len(removed) == 0 || contains(normAll(optionValues(ablocks[tIdx], lkey)), strings.Join(strings.Fields(val), " ")) {
						t.Fatalf("RemoveOptionValue diff removed=%q added=%q\n%s", removed, added, ctx)
					}
				}

			case 4: // AppendBlock: all old blocks identical, one new at the end
				if len(after) != len(bblocks)+1 {
					t.Fatalf("block count %d -> %d\n%s", len(bblocks), len(after), ctx)
				}
				for i := range bblocks {
					if !reflect.DeepEqual(ablocks[i], bblockRaws[i]) {
						t.Fatalf("existing block %d changed\n%s", i, ctx)
					}
				}
				if !reflect.DeepEqual(after[len(after)-1].Names, []string{newName}) {
					t.Fatalf("new block names %v\n%s", after[len(after)-1].Names, ctx)
				}
				// exactly one blank line between old content and the new block
				nb := after[len(after)-1]
				if nb.Start > 0 && strings.TrimSpace(d.Lines[nb.Start-1]) != "" {
					t.Fatalf("no blank separator\n%s", ctx)
				}
				if nb.Start > 1 && strings.TrimSpace(d.Lines[nb.Start-2]) == "" {
					t.Fatalf("more than one blank separator\n%s", ctx)
				}
				cfg, perr := Parse(d.Bytes())
				if perr != nil || cfg.Hosts[len(cfg.Hosts)-1].Name != newName || cfg.Hosts[len(cfg.Hosts)-1].Port != "22" {
					t.Fatalf("appended block does not parse back (Port 22 must be kept): %v\n%s", perr, ctx)
				}
				plain = append(plain, newName)

			case 5: // DeleteBlock
				if tIdx < 0 {
					t.Fatalf("delete of non-plain target succeeded\n%s", ctx)
				}
				if len(after) != len(bblocks)-1 {
					t.Fatalf("block count %d -> %d\n%s", len(bblocks), len(after), ctx)
				}
				var wantRaws [][]string
				for i, br := range bblockRaws {
					if i != tIdx {
						wantRaws = append(wantRaws, br)
					}
				}
				if !reflect.DeepEqual(ablocks, wantRaws) {
					t.Fatalf("remaining blocks differ\n%s", ctx)
				}
				tb := bblocks[tIdx]
				removedN := len(beforeLines) - len(d.Lines)
				if removedN != tb.End-tb.Start && removedN != tb.End-tb.Start+1 {
					t.Fatalf("removed %d lines, block has %d\n%s", removedN, tb.End-tb.Start, ctx)
				}
				cands := [][]string{
					append(append([]string(nil), beforeLines[:tb.Start]...), beforeLines[tb.End:]...),
				}
				if tb.End < len(beforeLines) {
					cands = append(cands, append(append([]string(nil), beforeLines[:tb.Start]...), beforeLines[tb.End+1:]...))
				}
				tailBlank := true
				for _, l := range beforeLines[tb.End:] {
					tailBlank = tailBlank && strings.TrimSpace(l) == ""
				}
				if tb.Start > 0 && tailBlank { // last block: the blank before may go
					cands = append(cands, append(append([]string(nil), beforeLines[:tb.Start-1]...), beforeLines[tb.End:]...))
				}
				ok := false
				for _, c := range cands {
					ok = ok || reflect.DeepEqual(c, d.Lines)
				}
				if !ok {
					t.Fatalf("result is not 'doc minus block (+ one adjacent blank)'\n%s", ctx)
				}
				plain = without(plain, target)

			case 6: // DuplicateBlock
				if tIdx < 0 {
					t.Fatalf("duplicate of non-plain target succeeded\n%s", ctx)
				}
				tb := bblocks[tIdx]
				if len(after) != len(bblocks)+1 {
					t.Fatalf("block count\n%s", ctx)
				}
				for i := range bblocks {
					j := i
					if i > tIdx {
						j = i + 1
					}
					if !reflect.DeepEqual(ablocks[j], bblockRaws[i]) {
						t.Fatalf("existing block %d changed\n%s", i, ctx)
					}
				}
				cp := ablocks[tIdx+1]
				if len(cp) != len(bblockRaws[tIdx]) {
					t.Fatalf("copy has %d lines, source %d\n%s", len(cp), len(bblockRaws[tIdx]), ctx)
				}
				removed, added := lineDiff(bblockRaws[tIdx], cp)
				if len(removed) != 1 || len(added) != 1 || lineKey(removed[0]) == "" || !strings.EqualFold(lineKey(removed[0]), "host") {
					t.Fatalf("copy differs from source in more than the Host line: -%q +%q\n%s", removed, added, ctx)
				}
				if !reflect.DeepEqual(after[tIdx+1].Names, []string{newName}) {
					t.Fatalf("copy names %v\n%s", after[tIdx+1].Names, ctx)
				}
				// prefix up to the source block's end, suffix from there on
				if !reflect.DeepEqual(d.Lines[:tb.End], beforeLines[:tb.End]) ||
					!reflect.DeepEqual(d.Lines[len(d.Lines)-(len(beforeLines)-tb.End):], beforeLines[tb.End:]) {
					t.Fatalf("lines outside the insertion changed\n%s", ctx)
				}
				plain = append(plain, newName)
			}
		}
		if err := docVsParse(d); err != nil {
			t.Fatalf("iter %d after the last step:\n%s\n%v", iter, strings.Join(d.Lines, "\n"), err)
		}
	}

	// The run must actually have exercised every operation, including
	// refusals; otherwise the property would be vacuous. (Thresholds are
	// asserted for the fixed seed; a random seed only has to do each at
	// least once.)
	min := 1
	if checkCounts {
		min = 20
	}
	for _, k := range []string{"SetOption", "UnsetOption", "AddOptionValue", "RemoveOptionValue", "AppendBlock", "DeleteBlock", "DuplicateBlock", "disable-enable"} {
		if counts[k] < min {
			t.Errorf("operation %s succeeded only %d times in 200 iterations: generator too weak (%v)", k, counts[k], counts)
		}
	}
	for _, k := range []string{"SetOption-err", "DeleteBlock-err"} {
		if counts[k] == 0 {
			t.Errorf("no %s observed: error paths unexercised (%v)", k, counts)
		}
	}
	t.Logf("operation counts: %v", counts)
}

// trimEdgeComments drops the comment-only lines at both ends of a block.
func trimEdgeComments(lines []string) []string {
	isComment := func(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "#") }
	a, b := 0, len(lines)
	for a < b && isComment(lines[a]) {
		a++
	}
	for b > a && isComment(lines[b-1]) {
		b--
	}
	return lines[a:b]
}

func untargetedRaws(d *Doc, bs []Block, targeted func(Block) bool) [][]string {
	var out [][]string
	for _, b := range bs {
		if !targeted(b) {
			out = append(out, append([]string(nil), d.Raw(b)...))
		}
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func normAll(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strings.Join(strings.Fields(x), " ")
	}
	return out
}

func without(xs []string, s string) []string {
	var out []string
	for _, x := range xs {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}
