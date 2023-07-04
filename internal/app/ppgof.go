package app

import (
	"net/http"

	"net/http/pprof"
)

// PProfHandler pprof http handler
func PProfHandler() http.Handler {
	const (
		pprofs = "/pprof"
	)
	r := http.NewServeMux()

	r.HandleFunc(pprofs+"/index", pprof.Index)
	r.HandleFunc(pprofs+"/profile", pprof.Profile)
	r.HandleFunc(pprofs+"/symbol", pprof.Symbol)
	r.HandleFunc(pprofs+"/trace", pprof.Trace)
	r.HandleFunc(pprofs+"/cmdline", pprof.Cmdline)

	r.Handle(pprofs+"/goroutine", pprof.Handler("goroutine"))
	r.Handle(pprofs+"/threadcreate", pprof.Handler("threadcreate"))
	r.Handle(pprofs+"/mutex", pprof.Handler("mutex"))
	r.Handle(pprofs+"/heap", pprof.Handler("heap"))
	r.Handle(pprofs+"/block", pprof.Handler("block"))
	r.Handle(pprofs+"/allocs", pprof.Handler("allocs"))

	return r
}
