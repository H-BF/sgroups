package patterns

import (
	"fmt"
	"regexp"
)

// Path -
type Path struct {
	string
}

// ErrBadPath impl error iface
type ErrBadPath struct {
	V string
}

// Error -
func (e ErrBadPath) Error() string {
	return fmt.Sprintf("Path: value '%s' is bad", e.V)
}

// String impl stronget iface
func (p Path) String() string {
	return p.string
}

// IsEmpty -
func (p Path) IsEmpty() bool {
	return len(p.string) == 0
}

// Set assigns value
func (p *Path) Set(s string) error {
	if !rePathValidator.MatchString(s) {
		return ErrBadPath{V: s}
	}
	if n := len(s); n > 0 && s[n-1] == '/' {
		p.string = s[:n-1]
	} else {
		p.string = s
	}
	return nil
}

var (
	rePathValidator = regexp.MustCompile(`^/?((?:\.*[^\s\\/\.]+\.*)+/?)*$`)
)
