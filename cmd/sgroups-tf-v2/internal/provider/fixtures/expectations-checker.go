package fixtures

// ExpectationsChecker -
type ExpectationsChecker[B BackendRC, D DomainRC] struct {
	weHaveDomains DomainRcList[D]
}

// Init -
func (exp *ExpectationsChecker[B, D]) Init(b []*B) {
	Backend2Domain(b, &exp.weHaveDomains)
}

// WeExpectFindAll -
func (exp ExpectationsChecker[B, D]) WeExpectFindAll(objs []*B) bool {
	var expect DomainRcList[D]
	Backend2Domain(objs, &expect)
	return len(expect) > 0 &&
		expect.AllIn(exp.weHaveDomains, true)
}

// WeDontExpectFindAny -
func (exp ExpectationsChecker[B, D]) WeDontExpectFindAny(objs []*B) bool {
	var dontExpect DomainRcList[D]
	Backend2Domain(objs, &dontExpect)
	return !dontExpect.AnyIn(exp.weHaveDomains, false)
}
