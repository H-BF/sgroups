package agent

import (
	"flag"
)

// ConfigFile file with actual app config
var ConfigFile string

func init() {
	flag.StringVar(&ConfigFile, "config", "", "app config file")
}
