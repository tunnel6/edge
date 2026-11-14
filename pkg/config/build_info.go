package config

import (
	"runtime"
)

var (
	Version = "1.3.0"
	Build   = "-" //time.Now().Format(time.RFC3339)
	Commit  = "-"
	Runtime = runtime.Version()
)

func GetVersionInfo() (string, string, string, string) {
	return Version, Build, Commit, Runtime
}
