package fixtures

import (
	"embed"
)

//go:embed *.yaml data/*.yaml
var data embed.FS
