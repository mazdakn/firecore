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

func (m *Matcher) Match(payload []byte) bool {
	return m.regex.Match(payload)
}

func (m *Matcher) String() string {
	return m.pattern
}
