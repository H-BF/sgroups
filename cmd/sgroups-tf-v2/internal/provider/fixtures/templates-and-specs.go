package fixtures

type (
	rcSpec interface {
		typeName() string
	}

	// SpecOfNetworks -
	SpecOfNetworks map[string]struct {
		Name string `yaml:"name"`
		Cidr string `yaml:"cidr"`
	}

	SpecOfSgs map[string]struct {
		Name          string   `yaml:"name"`
		DefaultAction string   `yaml:"default_action"`
		Networks      []string `yaml:"networks"`
		Logs          bool     `yaml:"logs"`
		Trace         bool     `yaml:"trace"`
	}
)

// typeName -
func (SpecOfNetworks) typeName() string {
	return "networks"
}

func (SpecOfSgs) typeName() string {
	return "security-groups"
}

// TODO: define all templates
const templates = `
{{define "networks"}}
{{range $K, $V := .Spec}}
  {{$K}} = {
    name = "{{$V.Name}}"
    cidr = "{{$V.Cidr}}"
  }
{{end}}
{{end}}
{{define "security-groups"}}
{{range $K, $V := .Spec}}
  {{$K}} = {
    name = "{{$V.Name}}"    
  }
{{end}}
{{end}}
resource "sgroups_<type-name>" "{{.Name}}" {
{{template "<type-name>" .}}
}
`
