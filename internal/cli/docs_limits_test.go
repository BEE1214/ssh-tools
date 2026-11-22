package cli

// P7 clause X5 (PLAN-p7.md), the limits list. README.md and ARCHITECTURE.md must
// each have a section whose heading says "limit" (README: "Known limitations")
// and, inside that section only, each of these limits as its own list item or
// sentence that names its topic:
//
//  1. multi-pattern Host lines cannot be edited
//  2. DevPod and Match blocks stay in the main file
//  3. clients that do not follow Include do not see the managed hosts
//  4. a dotfile manager that overwrites the main file drops the Include
//  5. SIGKILL during a save
//
// docs_test.go only looks for keywords anywhere in the README; that passes when
// the list is deleted but the words occur elsewhere, and it does not look at
// ARCHITECTURE.md at all. This test looks at the section only.

import (
	"regexp"
	"strings"
	"testing"
)

var (
	headingRe  = regexp.MustCompile(`^(#{1,6})\s+(.*?)\s*#*\s*$`)
	listItemRe = regexp.MustCompile(`^\s*([-*+]|\d+[.)])\s+`)
	sentenceRe = regexp.MustCompile(`([.!?])\s+`)
)

// limitsSection returns the body (heading excluded) of the first section whose
// heading contains "limit": from the heading to the next heading of the same
// or a higher level.
func limitsSection(doc string) (body string, heading string, ok bool) {
	lines := strings.Split(doc, "\n")
	inFence := false
	start, level := -1, 0
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		m := headingRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if start >= 0 {
			if len(m[1]) <= level {
				return strings.Join(lines[start+1:i], "\n"), heading, true
			}
			continue
		}
		if strings.Contains(strings.ToLower(m[2]), "limit") {
			start, level, heading = i, len(m[1]), l
		}
	}
	if start < 0 {
		return "", "", false
	}
	return strings.Join(lines[start+1:], "\n"), heading, true
}

// limitUnits splits a section body into the units a limit may live in: a list
// item (with its continuation lines) is one unit; the lines of any other
// paragraph are split into sentences.
func limitUnits(body string) []string {
	var units []string
	var para []string
	var item []string
	flushPara := func() {
		if len(para) > 0 {
			text := strings.Join(para, " ")
			for _, s := range strings.Split(sentenceRe.ReplaceAllString(text, "$1\n"), "\n") {
				if s = strings.TrimSpace(s); s != "" {
					units = append(units, s)
				}
			}
			para = nil
		}
	}
	flushItem := func() {
		if len(item) > 0 {
			units = append(units, strings.Join(item, " "))
			item = nil
		}
	}
	for _, l := range strings.Split(body, "\n") {
		switch {
		case strings.TrimSpace(l) == "":
			flushPara()
			flushItem()
		case listItemRe.MatchString(l):
			flushPara()
			flushItem()
			item = append(item, strings.TrimSpace(listItemRe.ReplaceAllString(l, "")))
		case len(item) > 0:
			item = append(item, strings.TrimSpace(l))
		default:
			para = append(para, strings.TrimSpace(l))
		}
	}
	flushPara()
	flushItem()
	return units
}

type limitTopic struct {
	name  string
	named func(low string) bool // low: lower-cased, backticks and asterisks removed
}

func hasAny(s string, kws ...string) bool {
	for _, k := range kws {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

var limitTopics = []limitTopic{
	{"multi-pattern Host lines", func(s string) bool { return hasAny(s, "multi-pattern", "several patterns") }},
	{"DevPod and Match blocks stay in the main file", func(s string) bool {
		return strings.Contains(s, "devpod") && strings.Contains(s, "match") && hasAny(s, "main file", "own file")
	}},
	{"clients that do not follow Include", func(s string) bool {
		return hasAny(s, "do not follow", "does not follow", "don't follow") && strings.Contains(s, "include") &&
			hasAny(s, "managed host", "not see")
	}},
	{"a dotfile manager overwrites the main file", func(s string) bool {
		return strings.Contains(s, "dotfile") && strings.Contains(s, "include") && hasAny(s, "overwrit")
	}},
	{"SIGKILL during a save", func(s string) bool { return strings.Contains(s, "sigkill") && strings.Contains(s, "save") }},
}

var plainRe = strings.NewReplacer("`", "", "*", "")

// checkLimits returns the problems of doc's limits list (empty: fine).
func checkLimits(doc string) []string {
	body, heading, ok := limitsSection(doc)
	if !ok {
		return []string{"no section whose heading contains \"limit\""}
	}
	var problems []string
	covered := map[string]string{} // topic -> the unit that names it
	for _, u := range limitUnits(body) {
		low := strings.ToLower(plainRe.Replace(u))
		var named []string
		for _, tp := range limitTopics {
			if tp.named(low) {
				named = append(named, tp.name)
			}
		}
		switch len(named) {
		case 0:
		case 1:
			if _, dup := covered[named[0]]; !dup {
				covered[named[0]] = u
			}
		default:
			problems = append(problems, "one sentence/list item covers several limits ("+strings.Join(named, "; ")+"): "+u)
		}
	}
	for _, tp := range limitTopics {
		if _, ok := covered[tp.name]; !ok {
			problems = append(problems, "section "+strings.TrimSpace(heading)+" has no own sentence/list item for: "+tp.name)
		}
	}
	if len(covered) < 5 {
		problems = append(problems, "fewer than five distinct limits inside the section")
	}
	return problems
}

func TestDocsLimits_README(t *testing.T) {
	readme, _ := docsText(t)
	for _, p := range checkLimits(readme) {
		t.Errorf("README.md: %s", p)
	}
}

func TestDocsLimits_Architecture(t *testing.T) {
	_, arch := docsText(t)
	for _, p := range checkLimits(arch) {
		t.Errorf("ARCHITECTURE.md: %s", p)
	}
}

// The checker itself: deleting the list, or the whole section, from the real
// documents must be caught; the list outside a limits section must not count.
func TestDocsLimits_CheckerDetectsDeletion(t *testing.T) {
	readme, _ := docsText(t)
	body, heading, ok := limitsSection(readme)
	if !ok {
		t.Skip("README has no limits section (TestDocsLimits_README reports it)")
	}
	full := readme
	if got := checkLimits(full); len(got) != 0 {
		t.Skipf("README limits list is incomplete (TestDocsLimits_README reports it): %v", got)
	}

	cases := map[string]string{
		"section removed":            strings.Replace(full, heading+"\n"+body, "", 1),
		"list items removed":         strings.Replace(full, body, "\n", 1),
		"heading renamed":            strings.Replace(full, heading, "## Notes", 1),
		"limits as one sentence":     strings.Replace(full, body, "\nsshm has multi-pattern limits; DevPod and Match blocks stay in the main file; clients that do not follow Include do not see managed hosts; a dotfile manager that overwrites the main file drops the Include; SIGKILL during a save.\n", 1),
		"one limit missing":          strings.Replace(full, body, strings.Join(limitUnitsWithout(body, "sigkill"), "\n"), 1),
		"list under another heading": strings.Replace(full, heading, "## Other\n\n"+body+"\n"+heading, 1),
	}
	for name, doc := range cases {
		if name == "list under another heading" {
			// The list stays in a section called "Other" and the real limits
			// section is emptied: must fail.
			doc = strings.Replace(doc, heading+"\n"+body, heading+"\n", 1)
		}
		if doc == full {
			t.Fatalf("%s: the mutation changed nothing", name)
		}
		if len(checkLimits(doc)) == 0 {
			t.Errorf("%s: checkLimits found no problem", name)
		}
	}
}

// limitUnitsWithout returns the lines of body without those that contain kw.
func limitUnitsWithout(body, kw string) []string {
	var out []string
	for _, l := range strings.Split(body, "\n") {
		if !strings.Contains(strings.ToLower(l), kw) {
			out = append(out, l)
		}
	}
	return out
}
