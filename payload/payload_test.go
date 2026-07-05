package payload

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	matcher, err := New(`GET /users/\d+`)
	Expect(err).ToNot(HaveOccurred())
	Expect(matcher).ToNot(BeNil())
	Expect(matcher.String()).To(Equal(`GET /users/\d+`))
}

func TestNewInvalidPattern(t *testing.T) {
	RegisterTestingT(t)

	matcher, err := New(`[`)
	Expect(err).To(HaveOccurred())
	Expect(matcher).To(BeNil())
}

func TestMatch(t *testing.T) {
	RegisterTestingT(t)

	matcher, err := New(`secret=\w+`)
	Expect(err).NotTo(HaveOccurred())

	Expect(matcher.Match([]byte("GET /?secret=token"))).To(BeTrue())
	Expect(matcher.Match([]byte("GET /?public=true"))).To(BeFalse())
}
