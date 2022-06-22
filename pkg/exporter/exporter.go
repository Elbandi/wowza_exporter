// Copyright 2020 The Prometheus Authors
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

package exporter

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	dac "github.com/JudgeGregg/go-http-digest-auth-client"
)

const (
	Namespace = "wowza"
)

// Exporter collects metrics from a wowza server.
type Exporter struct {
	hostname string
	port     int
	username string
	password string
	timeout  time.Duration
	logger   log.Logger
	client   *http.Client

	up                         *prometheus.Desc
	time                       *prometheus.Desc
	totalMetrics               map[string]*prometheus.Desc
	vhostMetrics               map[string]*prometheus.Desc
	applicationMetrics         map[string]*prometheus.Desc
	applicationInstanceMetrics map[string]*prometheus.Desc
}

func newServerMetric(metricName string, docString string, labels []string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, "", metricName),
		docString, labels, nil,
	)
}

func newVhostMetric(metricName string, docString string, labels []string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, "vhost", metricName),
		docString, append([]string{"vhost"}, labels...), nil,
	)
}

func newApplicationMetric(metricName string, docString string, labels []string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, "application", metricName),
		docString, append([]string{"vhost", "application"}, labels...), nil,
	)
}

func newApplicationInstanceMetric(metricName string, docString string, labels []string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, "instance", metricName),
		docString, append([]string{"vhost", "application", "instance"}, labels...), nil,
	)
}

// New returns an initialized exporter.
func New(hostname string, port int, username string, password string, logger log.Logger) *Exporter {
	return &Exporter{
		hostname: hostname,
		port:     port,
		username: username,
		password: password,
		logger:   logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		up: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "up"),
			"Could the wowza server be reached.",
			nil,
			nil,
		),
		time: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "time_seconds"),
			"current UNIX time according to the server.",
			nil,
			nil,
		),
		totalMetrics: map[string]*prometheus.Desc{
			"connections_current":        newServerMetric("connections_current", "ConnectionsCurrent", nil),
			"connections_total":          newServerMetric("connections_total", "ConnectionsTotal", nil),
			"connections_total_accepted": newServerMetric("connections_total_accepted", "ConnectionsTotalAccepted", nil),
			"connections_total_rejected": newServerMetric("connections_total_rejected", "ConnectionsTotalRejected", nil),
			"messages_bytes_rate":        newServerMetric("messages_bytes_rate", "MessagesBytesRate", []string{"type"}),
		},
		vhostMetrics: map[string]*prometheus.Desc{
			"connections_current":        newVhostMetric("connections_current", "ConnectionsCurrent", nil),
			"connections_total":          newVhostMetric("connections_total", "ConnectionsTotal", nil),
			"connections_total_accepted": newVhostMetric("connections_total_accepted", "ConnectionsTotalAccepted", nil),
			"connections_total_rejected": newVhostMetric("connections_total_rejected", "ConnectionsTotalRejected", nil),
			"messages_bytes_rate":        newVhostMetric("messages_bytes_rate", "MessagesBytesRate", []string{"type"}),
			"time_running":               newVhostMetric("time_running", "TimeRunning", nil),
		},
		applicationMetrics: map[string]*prometheus.Desc{
			"connections_current":        newApplicationMetric("connections_current", "ConnectionsCurrent", nil),
			"connections_total":          newApplicationMetric("connections_total", "ConnectionsTotal", nil),
			"connections_total_accepted": newApplicationMetric("connections_total_accepted", "ConnectionsTotalAccepted", nil),
			"connections_total_rejected": newApplicationMetric("connections_total_rejected", "ConnectionsTotalRejected", nil),
			"messages_bytes_rate":        newApplicationMetric("messages_bytes_rate", "MessagesBytesRate", []string{"type"}),
			"time_running":               newApplicationMetric("time_running", "TimeRunning", nil),
		},
		applicationInstanceMetrics: map[string]*prometheus.Desc{
			"connections_current":        newApplicationInstanceMetric("connections_current", "ConnectionsCurrent", nil),
			"connections_total":          newApplicationInstanceMetric("connections_total", "ConnectionsTotal", nil),
			"connections_total_accepted": newApplicationInstanceMetric("connections_total_accepted", "ConnectionsTotalAccepted", nil),
			"connections_total_rejected": newApplicationInstanceMetric("connections_total_rejected", "ConnectionsTotalRejected", nil),
			"messages_bytes_rate":        newApplicationInstanceMetric("messages_bytes_rate", "MessagesBytesRate", []string{"type"}),
			"time_running":               newApplicationInstanceMetric("time_running", "TimeRunning", nil),
			"stream_count":               newApplicationInstanceMetric("stream_count", "StreamCount", nil),
		},
	}
}

// Describe describes all the metrics exported by the wowza exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.up
	ch <- e.time
	for _, m := range e.totalMetrics {
		ch <- m
	}
	for _, m := range e.vhostMetrics {
		ch <- m
	}
	for _, m := range e.applicationMetrics {
		ch <- m
	}
	for _, m := range e.applicationInstanceMetrics {
		ch <- m
	}
}

// Collect fetches the statistics from the configured wowza server, and
// delivers them as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	response, err := e.readClusterStats()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, 0)
		level.Error(e.logger).Log("msg", "Failed to connect to wowza", "err", err)
		return
	}

	up := float64(1)
	if err := e.parseStats(ch, response); err != nil {
		up = 0
	}

	ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, up)
}

func (e *Exporter) readClusterStats() (Response, error) {
	//	http.DefaultClient.Timeout = timeout
	//	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: *insecure}
	t := dac.NewTransport(e.username, e.password)

	apiStatsUrl := fmt.Sprintf("http://%s:%d/%s", e.hostname, e.port, "connectioncounts")
	req, err := http.NewRequest("GET", apiStatsUrl, nil)
	if err != nil {
		return Response{}, err
	}

	req.SetBasicAuth(e.username, e.password)

	resp, err := t.RoundTrip(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()

	if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
		return Response{}, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Response{}, err
	}

	var response Response
	err = xml.Unmarshal(body, &response)
	if err != nil {
		return Response{}, err
	}

	return response, nil
}

func (e *Exporter) parseStats(ch chan<- prometheus.Metric, response Response) error {
	//	ch <- prometheus.MustNewConstMetric(e.infoMetric, prometheus.GaugeValue, float64(uptime), nginxVtx.HostName, nginxVtx.NginxVersion)
	ch <- prometheus.MustNewConstMetric(
		e.totalMetrics["connections_current"], prometheus.CounterValue, float64(response.ConnectionsCurrent),
	)
	ch <- prometheus.MustNewConstMetric(
		e.totalMetrics["connections_total"], prometheus.CounterValue, float64(response.ConnectionsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		e.totalMetrics["connections_total_accepted"], prometheus.CounterValue, float64(response.ConnectionsTotalAccepted),
	)
	ch <- prometheus.MustNewConstMetric(
		e.totalMetrics["connections_total_rejected"], prometheus.CounterValue, float64(response.ConnectionsTotalRejected),
	)
	ch <- prometheus.MustNewConstMetric(
		e.totalMetrics["messages_bytes_rate"], prometheus.GaugeValue, float64(response.MessagesInBytesRate), "in",
	)
	ch <- prometheus.MustNewConstMetric(
		e.totalMetrics["messages_bytes_rate"], prometheus.GaugeValue, float64(response.MessagesOutBytesRate), "out",
	)
	for _, vhost := range response.VHost {
		vhostName := vhost.Name
		ch <- prometheus.MustNewConstMetric(
			e.vhostMetrics["connections_current"], prometheus.CounterValue, float64(vhost.ConnectionsCurrent), vhostName,
		)
		ch <- prometheus.MustNewConstMetric(
			e.vhostMetrics["connections_total"], prometheus.CounterValue, float64(vhost.ConnectionsTotal), vhostName,
		)
		ch <- prometheus.MustNewConstMetric(
			e.vhostMetrics["connections_total_accepted"], prometheus.CounterValue, float64(vhost.ConnectionsTotalAccepted), vhostName,
		)
		ch <- prometheus.MustNewConstMetric(
			e.vhostMetrics["connections_total_rejected"], prometheus.CounterValue, float64(vhost.ConnectionsTotalRejected), vhostName,
		)
		ch <- prometheus.MustNewConstMetric(
			e.vhostMetrics["messages_bytes_rate"], prometheus.GaugeValue, float64(vhost.MessagesInBytesRate), vhostName, "in",
		)
		ch <- prometheus.MustNewConstMetric(
			e.vhostMetrics["messages_bytes_rate"], prometheus.GaugeValue, float64(vhost.MessagesOutBytesRate), vhostName, "out",
		)
		ch <- prometheus.MustNewConstMetric(
			e.vhostMetrics["time_running"], prometheus.CounterValue, float64(vhost.TimeRunning), vhostName,
		)

		for _, application := range vhost.Application {
			applicationName := application.Name
			ch <- prometheus.MustNewConstMetric(
				e.applicationMetrics["connections_current"], prometheus.CounterValue, float64(application.ConnectionsCurrent), vhostName, applicationName,
			)
			ch <- prometheus.MustNewConstMetric(
				e.applicationMetrics["connections_total"], prometheus.CounterValue, float64(application.ConnectionsTotal), vhostName, applicationName,
			)
			ch <- prometheus.MustNewConstMetric(
				e.applicationMetrics["connections_total_accepted"], prometheus.CounterValue, float64(application.ConnectionsTotalAccepted), vhostName, applicationName,
			)
			ch <- prometheus.MustNewConstMetric(
				e.applicationMetrics["connections_total_rejected"], prometheus.CounterValue, float64(application.ConnectionsTotalRejected), vhostName, applicationName,
			)
			ch <- prometheus.MustNewConstMetric(
				e.applicationMetrics["messages_bytes_rate"], prometheus.GaugeValue, float64(application.MessagesInBytesRate), vhostName, applicationName, "in",
			)
			ch <- prometheus.MustNewConstMetric(
				e.applicationMetrics["messages_bytes_rate"], prometheus.GaugeValue, float64(application.MessagesOutBytesRate), vhostName, applicationName, "out",
			)
			ch <- prometheus.MustNewConstMetric(
				e.applicationMetrics["time_running"], prometheus.CounterValue, float64(application.TimeRunning), vhostName, applicationName,
			)

			for _, instance := range application.ApplicationInstance {
				instanceName := instance.Name
				ch <- prometheus.MustNewConstMetric(
					e.applicationInstanceMetrics["connections_current"], prometheus.CounterValue, float64(instance.ConnectionsCurrent), vhostName, applicationName, instanceName,
				)
				ch <- prometheus.MustNewConstMetric(
					e.applicationInstanceMetrics["connections_total"], prometheus.CounterValue, float64(instance.ConnectionsTotal), vhostName, applicationName, instanceName,
				)
				ch <- prometheus.MustNewConstMetric(
					e.applicationInstanceMetrics["connections_total_accepted"], prometheus.CounterValue, float64(instance.ConnectionsTotalAccepted), vhostName, applicationName, instanceName,
				)
				ch <- prometheus.MustNewConstMetric(
					e.applicationInstanceMetrics["connections_total_rejected"], prometheus.CounterValue, float64(instance.ConnectionsTotalRejected), vhostName, applicationName, instanceName,
				)
				ch <- prometheus.MustNewConstMetric(
					e.applicationInstanceMetrics["messages_bytes_rate"], prometheus.GaugeValue, float64(instance.MessagesInBytesRate), vhostName, applicationName, "in", instanceName,
				)
				ch <- prometheus.MustNewConstMetric(
					e.applicationInstanceMetrics["messages_bytes_rate"], prometheus.GaugeValue, float64(instance.MessagesOutBytesRate), vhostName, applicationName, "out", instanceName,
				)
				ch <- prometheus.MustNewConstMetric(
					e.applicationInstanceMetrics["time_running"], prometheus.CounterValue, float64(instance.TimeRunning), vhostName, applicationName, instanceName,
				)
				ch <- prometheus.MustNewConstMetric(
					e.applicationInstanceMetrics["stream_count"], prometheus.CounterValue, float64(len(instance.Stream)), vhostName, applicationName, instanceName,
				)
			}

		}
	}
	return nil
}

type ApplicationInstance struct {
	Name                     string        `xml:"Name"`
	Status                   string        `xml:"Status"`
	TimeRunning              float64       `xml:"TimeRunning"`
	ConnectionsCurrent       int           `xml:"ConnectionsCurrent"`
	ConnectionsTotal         int           `xml:"ConnectionsTotal"`
	ConnectionsTotalAccepted int           `xml:"ConnectionsTotalAccepted"`
	ConnectionsTotalRejected int           `xml:"ConnectionsTotalRejected"`
	MessagesInBytesRate      float64       `xml:"MessagesBytesRate"`
	MessagesOutBytesRate     float64       `xml:"MessagesOutBytesRate"`
	Stream                   []interface{} `xml:"Stream"`
}

type Application struct {
	Name                     string                `xml:"Name"`
	Status                   string                `xml:"Status"`
	TimeRunning              float64               `xml:"TimeRunning"`
	ConnectionsCurrent       int                   `xml:"ConnectionsCurrent"`
	ConnectionsTotal         int                   `xml:"ConnectionsTotal"`
	ConnectionsTotalAccepted int                   `xml:"ConnectionsTotalAccepted"`
	ConnectionsTotalRejected int                   `xml:"ConnectionsTotalRejected"`
	MessagesInBytesRate      float64               `xml:"MessagesBytesRate"`
	MessagesOutBytesRate     float64               `xml:"MessagesOutBytesRate"`
	ApplicationInstance      []ApplicationInstance `xml:"ApplicationInstance"`
}

type VHost struct {
	Name                     string        `xml:"Name"`
	TimeRunning              float64       `xml:"TimeRunning"`
	ConnectionsLimit         int           `xml:"ConnectionsLimit"`
	ConnectionsCurrent       int           `xml:"ConnectionsCurrent"`
	ConnectionsTotal         int           `xml:"ConnectionsTotal"`
	ConnectionsTotalAccepted int           `xml:"ConnectionsTotalAccepted"`
	ConnectionsTotalRejected int           `xml:"ConnectionsTotalRejected"`
	MessagesInBytesRate      float64       `xml:"MessagesBytesRate"`
	MessagesOutBytesRate     float64       `xml:"MessagesOutBytesRate"`
	Application              []Application `xml:"Application"`
}

type Response struct {
	ConnectionsCurrent       int     `xml:"ConnectionsCurrent"`
	ConnectionsTotal         int     `xml:"ConnectionsTotal"`
	ConnectionsTotalAccepted int     `xml:"ConnectionsTotalAccepted"`
	ConnectionsTotalRejected int     `xml:"ConnectionsTotalRejected"`
	MessagesInBytesRate      float64 `xml:"MessagesBytesRate"`
	MessagesOutBytesRate     float64 `xml:"MessagesOutBytesRate"`
	VHost                    []VHost `xml:"VHost"`
}
