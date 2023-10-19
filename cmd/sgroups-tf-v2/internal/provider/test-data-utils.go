package provider

import (
	"fmt"
	"strings"
)

const (
	networksTemplate = `
resource "sgroups_networks" "test" {
	items = {
		%s
	}
}`
	networkItemTemplate = `
		"%s" = {
			name = "%s"
			cidr = "%s"
		}
`
	sgsTemplate = `
resource "sgroups_groups" "test" {
	items = {
		%s
	}
}`
	sgItemTemplate = `
		"%s" = {
			name = "%s"
			logs = %t
			trace = %t
			default_action = "%s"
			networks = [%s]
		}
`
	sgSgRulesTemplate = `
resource "sgroups_rules" "test" {
	items = {
		%s
	}
}`
	sgSgRuleItemTemplate = `
		"%s" = {
			proto = "%s"
            sg_from = "%s"
            sg_to = "%s"
            logs = %t
            ports = [
				%s
            ]
		}
`
	sgFqdnRulesTemplate = `
resource "sgroups_fqdn_rules" "test" {
	items = {
		%s
	}
}`
	sgFqdnRuleItemTemplate = `
		"%s" = {
			proto = "%s"
			sg_from = "%s"
			fqdn = "%s"
			logs = %t
			ports = [
				%s
			]
		}
`
)

type (
	testDataItem interface {
		Format() string
	}

	networkTestData struct {
		name string
		cidr string
	}

	sgTestData struct {
		name          string
		logs          bool
		trace         bool
		defaultAction string
		network_names []string
	}

	sgSgRuleTestData struct {
		proto string
		from  string
		to    string
		logs  bool
		ports []accPorts
	}

	sgFqdnRuleTestData struct {
		proto string
		from  string
		to    string
		logs  bool
		ports []accPorts
	}

	accPorts struct {
		d string
		s string
	}
)

func (d networkTestData) Format() string {
	return fmt.Sprintf(networkItemTemplate, d.name, d.name, d.cidr)
}

func (d sgTestData) Format() string {
	nets := make([]string, 0, len(d.network_names))
	for _, net := range d.network_names {
		nets = append(nets, fmt.Sprintf(`"%s"`, net))
	}

	return fmt.Sprintf(sgItemTemplate,
		d.name,
		d.name,
		d.logs,
		d.trace,
		d.defaultAction,
		strings.Join(nets, ","))
}

func (d sgSgRuleTestData) Format() string {
	portsData := make([]string, 0, len(d.ports))
	for _, ports := range d.ports {
		portsData = append(portsData, ports.Format())
	}
	return fmt.Sprintf(sgSgRuleItemTemplate,
		d.FormatKey(),
		d.proto,
		d.from,
		d.to,
		d.logs,
		strings.Join(portsData, ",\n"))
}

func (d sgSgRuleTestData) FormatKey() string {
	return fmt.Sprintf("%s:sg(%s)sg(%s)", d.proto, d.from, d.to)
}

func (d sgFqdnRuleTestData) Format() string {
	portsData := make([]string, 0, len(d.ports))
	for _, ports := range d.ports {
		portsData = append(portsData, ports.Format())
	}
	return fmt.Sprintf(sgFqdnRuleItemTemplate,
		d.FormatKey(),
		d.proto,
		d.from,
		d.to,
		d.logs,
		strings.Join(portsData, ",\n"))
}

func (d sgFqdnRuleTestData) FormatKey() string {
	return fmt.Sprintf("%s:sg(%s)fqdn(%s)", d.proto, d.from, d.to)
}

func (d accPorts) Format() string {
	template := `{
			d = "%s"
			s = "%s"
		}`
	return fmt.Sprintf(template, d.d, d.s)
}

func buildConfig(configTemplate string, fst testDataItem, others ...testDataItem) string {
	items := strings.Builder{}
	items.WriteString(fst.Format())
	for _, i := range others {
		items.WriteString(i.Format())
	}

	return fmt.Sprintf(configTemplate, items.String())
}
