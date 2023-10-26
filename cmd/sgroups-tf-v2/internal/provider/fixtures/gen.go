package fixtures

import (
	"embed"
	"html/template"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed */*.yaml
var data embed.FS

type (
	// AbstractRC -
	AbstractRC[specT rcSpec] struct {
		Name string `yaml:"name"`
		Spec specT  `yaml:"spec"`
	}

	// NetworksRC -
	NetworksRC = AbstractRC[SpecOfNetworks]

	// SgsRC -
	SgsRC = AbstractRC[SpecOfSgs]
)

// LoadFixture -
func (rc *AbstractRC[specT]) LoadFixture(fixtureName string) error {
	f, e := data.Open(fixtureName)
	if e != nil {
		return e
	}
	defer f.Close() //nolint
	return yaml.NewDecoder(f).Decode(rc)
}

// TfRcConf -
func (rc AbstractRC[specT]) TfRcConf(out io.Writer) error {
	templateSource := strings.ReplaceAll(
		templates, "<type-name>", rc.Spec.typeName(),
	)
	tp, err := template.New("all").Parse(templateSource)
	if err != nil {
		return err
	}
	return tp.Execute(out, rc)
}
