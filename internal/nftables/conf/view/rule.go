package view

// RuleView - view of rule from netlink
type RuleView struct {
	Chain      string
	Table      string
	Family     string
	Comment    string
	Action     string
	Handle     string
	Interfaces struct {
		Input  []string
		Output []string
	}
	Addresses struct {
		Source      []string
		Destination []string
	}
	Ports struct {
		Source      []string
		Destination []string
	}
	*Counter
}

type Counter struct {
	Bytes   float64
	Packets float64
}
