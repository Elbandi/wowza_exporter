// Copyright 2019 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"github.com/BurntSushi/toml"
	"net/http"
	"os"

	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/Elbandi/wowza_exporter/pkg/exporter"
)

type WowzaConfig struct {
	Hostname string `toml:"host"  default:"localhost" json:"host"`
	Port     int    `toml:"port"  default:"8086" json:"port"`
	Username string `toml:"username" json:"username"`
	Password string `toml:"password" json:"password"`
}

type Config struct {
	Wowza WowzaConfig `toml:"wowza" json:"wowza"`
}

func main() {
	var (
		configFile    = kingpin.Flag("wowza.config", "wowza config.").Default("/etc/promethus/wowza.conf").String()
		pidFile       = kingpin.Flag("wowza.pid-file", "Optional path to a file containing the wowza PID for additional metrics.").Default("").String()
		webConfig     = webflag.AddFlags(kingpin.CommandLine)
		listenAddress = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9968").String()
		metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
	)
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.HelpFlag.Short('h')
	kingpin.Version(version.Print("wowza_exporter"))
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting wowza_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())
	var config Config
	config.Wowza.Hostname = "localhost"
	config.Wowza.Port = 8086

	_, err := toml.DecodeFile(*configFile, &config)
	if err != nil {
		level.Error(logger).Log("msg", "Error read the config", "err", err)
		os.Exit(1)
	}

	prometheus.MustRegister(version.NewCollector("wowza_exporter"))
	prometheus.MustRegister(exporter.New(config.Wowza.Hostname, config.Wowza.Port, config.Wowza.Username, config.Wowza.Password, logger))

	if *pidFile != "" {
		procExporter := collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
			PidFn:     prometheus.NewPidFileFn(*pidFile),
			Namespace: exporter.Namespace,
		})
		prometheus.MustRegister(procExporter)
	}

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Wowza Exporter</title></head>
             <body>
             <h1>Wowza Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})

	level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)
	srv := &http.Server{Addr: *listenAddress}
	if err := web.ListenAndServe(srv, *webConfig, logger); err != nil {
		level.Error(logger).Log("msg", "Error running HTTP server", "err", err)
		os.Exit(1)
	}
}
