package config

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

var (
	globalConfig atomic.Value
)

type (
	//Option config init option
	Option interface {
		configOptionIs()
	}

	//WithSourceFile option
	WithSourceFile struct {
		Option
		FileName string
	}

	//WithSource option
	WithSource struct {
		Option
		Source io.Reader
		Type   string
	}

	//WithDefValue option
	WithDefValue struct {
		Option
		Key interface{}
		Val interface{}
	}

	//WithAcceptEnvironment option
	WithAcceptEnvironment struct {
		Option
		EnvPrefix string
	}
)

func configStore() *viper.Viper {
	ret, _ := globalConfig.Load().(*viper.Viper)
	return ret
}

//InitGlobalConfig init global config
func InitGlobalConfig(opts ...Option) error {
	const api = "InitGlobalConfig"

	cfgHolder := viper.NewWithOptions(viper.KeyDelimiter("/"),
		viper.EnvKeyReplacer(strings.NewReplacer("/", "_")))

	keyType := reflect.TypeOf((*string)(nil)).Elem()

	for _, opt := range opts {
		switch t := opt.(type) {
		case WithDefValue:
			if !reflect.TypeOf(t.Key).ConvertibleTo(keyType) {
				return errors.Wrapf(errors.New("no possible set default with key)"),
					"%s: key type '%T'", api, t)
			}
			k := reflect.ValueOf(t.Key).Convert(keyType).Interface().(string)
			cfgHolder.SetDefault(k, t.Val)
		case WithSourceFile:
			if len(t.FileName) == 0 {
				break
			}
			ext := filepath.Ext(t.FileName)
			if len(ext) == 0 {
				return errors.Wrapf(errors.New("no file type provided"),
					"%s: open file '%s'", api, t.FileName)
			}
			f, e := os.Open(t.FileName)
			if e != nil {
				return errors.Wrapf(e, "%s: open file '%s'", api, t.FileName)
			}
			cfgHolder.SetConfigType(ext[1:])
			e = cfgHolder.MergeConfig(f)
			_ = f.Close()
			if e != nil {
				return errors.Wrapf(e, "%s: consume config file '%s'", api, t.FileName)
			}
		case WithSource:
			cfgHolder.SetConfigType(t.Type)
			if e := cfgHolder.MergeConfig(t.Source); e != nil {
				return errors.Wrapf(e, "%s: consume source type '%s'", api, t.Type)
			}
		case WithAcceptEnvironment:
			cfgHolder.AutomaticEnv()
			cfgHolder.SetEnvPrefix(t.EnvPrefix)
		default:
			return errors.Wrapf(errors.New("unexpected option"),
				"%s: consume source type '%T'", api, opt)
		}
	}
	globalConfig.Store(cfgHolder)
	return nil
}

func init() {
	globalConfig.Store(viper.New())
}
