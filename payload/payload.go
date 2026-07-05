package payload

import "regexp"

// Matcher applies a compiled regular expression to packet payload bytes.
type Matcher struct {
	pattern string
	regex   *regexp.Regexp
}

func New(pattern string) (*Matcher, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &Matcher{
		pattern: pattern,
		regex:   regex,
	}, nil
}

func MustNew(pattern string) *Matcher {
	m, err := New(pattern)
	if err != nil {
		panic(err)
	}
	return m
}

func (m *Matcher) Match(payload []byte) bool {
	return m != nil && m.regex.Match(payload)
}

func (m *Matcher) String() string {
	if m == nil {
		return ""
	}
	return m.pattern
}
