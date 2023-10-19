package provider

import (
	"fmt"
	"strconv"
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

func buildConfig(configTemplate string, fst testDataItem, others ...testDataItem) string {
	items := strings.Builder{}
	items.WriteString(fst.Format())
	for _, i := range others {
		items.WriteString(i.Format())
	}

	return fmt.Sprintf(configTemplate, items.String())
}
