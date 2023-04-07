package core

import (
	"github.com/op/go-logging"
	"os"
)

var lg *logging.Logger

func Logger() *logging.Logger {
	if lg == nil {
		lg = logging.MustGetLogger("chaincode")
		formatStr := os.Getenv("CORE_CHAINCODE_LOGGING_FORMAT")
		if formatStr == "" {
			formatStr = "%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}"
		}
		format := logging.MustStringFormatter(formatStr)
		stderr := logging.NewLogBackend(os.Stderr, "", 0)
		formatted := logging.NewBackendFormatter(stderr, format)
		levelStr := os.Getenv("CORE_CHAINCODE_LOGGING_LEVEL")
		if levelStr == "" {
			levelStr = "warning"
		}
		level, err := logging.LogLevel(levelStr)
		if err != nil {
			panic(err)
		}
		leveled := logging.AddModuleLevel(formatted)
		leveled.SetLevel(level, "")
		lg.SetBackend(leveled)
	}
	return lg
}
