package metrics

import (
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/biter777/countries"
	"github.com/cloudflare/cloudflare-go"
	cloudflareAPI "github.com/lablabs/cloudflare-exporter/internal/cloudflare"
	"github.com/lablabs/cloudflare-exporter/internal/models"
	"github.com/prometheus/client_golang/prometheus"
	logging "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// MetricName represent metric name
type MetricName string

func (mn MetricName) String() string {
	return string(mn)
}

const (
	zoneRequestTotalMetricName                   MetricName = "cloudflare_zone_requests_total"
	zoneRequestCachedMetricName                  MetricName = "cloudflare_zone_requests_cached"
	zoneRequestSSLEncryptedMetricName            MetricName = "cloudflare_zone_requests_ssl_encrypted"
	zoneRequestContentTypeMetricName             MetricName = "cloudflare_zone_requests_content_type"
	zoneRequestCountryMetricName                 MetricName = "cloudflare_zone_requests_country"
	zoneRequestHTTPStatusMetricName              MetricName = "cloudflare_zone_requests_status"
	zoneRequestBrowserMapMetricName              MetricName = "cloudflare_zone_requests_browser_map_page_views_count"
	zoneRequestOriginStatusCountryHostMetricName MetricName = "cloudflare_zone_requests_origin_status_country_host"
	zoneRequestStatusCountryHostMetricName       MetricName = "cloudflare_zone_requests_status_country_host"
	zoneBandwidthTotalMetricName                 MetricName = "cloudflare_zone_bandwidth_total"
	zoneBandwidthCachedMetricName                MetricName = "cloudflare_zone_bandwidth_cached"
	zoneBandwidthSSLEncryptedMetricName          MetricName = "cloudflare_zone_bandwidth_ssl_encrypted"
	zoneBandwidthContentTypeMetricName           MetricName = "cloudflare_zone_bandwidth_content_type"
	zoneBandwidthCountryMetricName               MetricName = "cloudflare_zone_bandwidth_country"
	zoneThreatsTotalMetricName                   MetricName = "cloudflare_zone_threats_total"
	zoneThreatsCountryMetricName                 MetricName = "cloudflare_zone_threats_country"
	zoneThreatsTypeMetricName                    MetricName = "cloudflare_zone_threats_type"
	zonePageviewsTotalMetricName                 MetricName = "cloudflare_zone_pageviews_total"
	zoneUniquesTotalMetricName                   MetricName = "cloudflare_zone_uniques_total"
	zoneColocationVisitsMetricName               MetricName = "cloudflare_zone_colocation_visits"
	zoneColocationEdgeResponseBytesMetricName    MetricName = "cloudflare_zone_colocation_edge_response_bytes"
	zoneColocationRequestsTotalMetricName        MetricName = "cloudflare_zone_colocation_requests_total"
	zoneFirewallEventsCountMetricName            MetricName = "cloudflare_zone_firewall_events_count"
	zoneHealthCheckEventsOriginCountMetricName   MetricName = "cloudflare_zone_health_check_events_origin_count"
	workerRequestsMetricName                     MetricName = "cloudflare_worker_requests_count"
	workerErrorsMetricName                       MetricName = "cloudflare_worker_errors_count"
	workerCPUTimeMetricName                      MetricName = "cloudflare_worker_cpu_time"
	workerDurationMetricName                     MetricName = "cloudflare_worker_duration"
	poolHealthStatusMetricName                   MetricName = "cloudflare_zone_pool_health_status"
	poolRequestsTotalMetricName                  MetricName = "cloudflare_zone_pool_requests_total"
	logpushFailedJobsAccountMetricName           MetricName = "cloudflare_logpush_failed_jobs_account_count"
	logpushFailedJobsZoneMetricName              MetricName = "cloudflare_logpush_failed_jobs_zone_count"
	// new added
	zoneCustomerError4xxRate               MetricName = "cloudflare_zone_customer_error_4xx_rate"
	zoneCustomerError5xxRate               MetricName = "cloudflare_zone_customer_error_5xx_rate"
	zoneEdgeErrorRate                      MetricName = "cloudflare_zone_edge_error_rate"
	zoneOriginErrorRate                    MetricName = "cloudflare_zone_origin_error_rate"
	zoneBotRequestsByCountry               MetricName = "cloudflare_zone_bot_request_by_country"
	zoneCacheHitRatio                      MetricName = "cloudflare_zone_cache_hit_ratio"
	zoneHealthCheckEventsAdaptiveGroupsAvg MetricName = "cloudflare_zone_health_check_events_avg"
	zoneFirewallBotsDetectedSource         MetricName = "cloudflare_zone_firewall_bots_detected"
	zoneFirewallRequestAction              MetricName = "cloudflare_zone_firewall_request_action"
	zoneRequestMethodCount                 MetricName = "cloudflare_zone_request_method_count"
	magicTransitActiveTunnels              MetricName = "cloudflare_magic_transit_active_tunnels"
	magicTransitHealthyTunnels             MetricName = "cloudflare_magic_transit_healthy_tunnels"
	magicTransitTunnelFailures             MetricName = "cloudflare_magic_transit_tunnel_failures"
	magicTransitEdgeColoCount              MetricName = "cloudflare_magic_transit_edge_colo_count"
	zoneCertificateValidationStatus        MetricName = "cloudflare_zone_certificate_validation_status"
)

// Set map to check metric name availability.
type Set map[MetricName]struct{}

// Has function check and return bool for metric availability.
func (ms Set) Has(mn MetricName) bool {
	_, exists := ms[mn]
	return exists
}

// Add function add metric name.
func (ms Set) Add(mn MetricName) {
	ms[mn] = struct{}{}
}

var (
	// Requests
	zoneRequestTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneRequestTotalMetricName.String(),
		Help: "Number of requests for zone",
	}, []string{"zone", "account"},
	)

	zoneRequestCached = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneRequestCachedMetricName.String(),
		Help: "Number of cached requests for zone",
	}, []string{"zone", "account"},
	)

	zoneRequestSSLEncrypted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneRequestSSLEncryptedMetricName.String(),
		Help: "Number of encrypted requests for zone",
	}, []string{"zone", "account"},
	)

	zoneRequestContentType = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneRequestContentTypeMetricName.String(),
		Help: "Number of request for zone per content type",
	}, []string{"zone", "account", "content_type"},
	)

	zoneRequestCountry = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneRequestCountryMetricName.String(),
		Help: "Number of request for zone per country",
	}, []string{"zone", "account", "country", "region"},
	)

	zoneRequestHTTPStatus = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneRequestHTTPStatusMetricName.String(),
		Help: "Number of request for zone per HTTP status",
	}, []string{"zone", "account", "status"},
	)

	zoneRequestBrowserMap = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneRequestBrowserMapMetricName.String(),
		Help: "Number of successful requests for HTML pages per zone",
	}, []string{"zone", "account", "family"},
	)

	zoneRequestOriginStatusCountryHost = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneRequestOriginStatusCountryHostMetricName.String(),
		Help: "Count of not cached requests for zone per origin HTTP status per country per host",
	}, []string{"zone", "account", "status", "country", "host"},
	)

	zoneRequestStatusCountryHost = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneRequestStatusCountryHostMetricName.String(),
		Help: "Count of requests for zone per edge HTTP status per country per host",
	}, []string{"zone", "account", "status", "country", "host"},
	)

	zoneBandwidthTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneBandwidthTotalMetricName.String(),
		Help: "Total bandwidth per zone in bytes",
	}, []string{"zone", "account"},
	)

	zoneBandwidthCached = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneBandwidthCachedMetricName.String(),
		Help: "Cached bandwidth per zone in bytes",
	}, []string{"zone", "account"},
	)

	zoneBandwidthSSLEncrypted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneBandwidthSSLEncryptedMetricName.String(),
		Help: "Encrypted bandwidth per zone in bytes",
	}, []string{"zone", "account"},
	)

	zoneBandwidthContentType = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneBandwidthContentTypeMetricName.String(),
		Help: "Bandwidth per zone per content type",
	}, []string{"zone", "account", "content_type"},
	)

	zoneBandwidthCountry = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneBandwidthCountryMetricName.String(),
		Help: "Bandwidth per country per zone",
	}, []string{"zone", "account", "country", "region"},
	)

	zoneThreatsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneThreatsTotalMetricName.String(),
		Help: "Threats per zone",
	}, []string{"zone", "account"},
	)

	zoneThreatsCountry = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneThreatsCountryMetricName.String(),
		Help: "Threats per zone per country",
	}, []string{"zone", "account", "country", "region"},
	)

	zoneThreatsType = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneThreatsTypeMetricName.String(),
		Help: "Threats per zone per type",
	}, []string{"zone", "account", "type"},
	)

	zonePageviewsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zonePageviewsTotalMetricName.String(),
		Help: "Pageviews per zone",
	}, []string{"zone", "account"},
	)

	zoneUniquesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneUniquesTotalMetricName.String(),
		Help: "Uniques per zone",
	}, []string{"zone", "account"},
	)

	zoneColocationVisits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneColocationVisitsMetricName.String(),
		Help: "Total visits per colocation",
	}, []string{"zone", "account", "colocation", "host"},
	)

	zoneColocationEdgeResponseBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneColocationEdgeResponseBytesMetricName.String(),
		Help: "Edge response bytes per colocation",
	}, []string{"zone", "account", "colocation", "host"},
	)

	zoneColocationRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneColocationRequestsTotalMetricName.String(),
		Help: "Total requests per colocation",
	}, []string{"zone", "account", "colocation", "host"},
	)

	zoneFirewallEventsCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneFirewallEventsCountMetricName.String(),
		Help: "Count of Firewall events",
	}, []string{"zone", "account"},
	)

	zoneHealthCheckEventsOriginCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneHealthCheckEventsOriginCountMetricName.String(),
		Help: "Number of Heath check events per region per origin",
	}, []string{"zone", "account", "health_status", "origin_ip", "region", "fqdn"},
	)

	workerRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: workerRequestsMetricName.String(),
		Help: "Number of requests sent to worker by script name",
	}, []string{"script_name", "account"},
	)

	workerErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: workerErrorsMetricName.String(),
		Help: "Number of errors by script name",
	}, []string{"script_name", "account"},
	)

	workerCPUTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: workerCPUTimeMetricName.String(),
		Help: "CPU time quantiles by script name",
	}, []string{"script_name", "account", "quantile"},
	)

	workerDuration = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: workerDurationMetricName.String(),
		Help: "Duration quantiles by script name (GB*s)",
	}, []string{"script_name", "account", "quantile"},
	)

	poolHealthStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: poolHealthStatusMetricName.String(),
		Help: "Reports the health of a pool, 1 for healthy, 0 for unhealthy.",
	},
		[]string{"zone", "account", "load_balancer_name", "pool_name"},
	)

	poolRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: poolRequestsTotalMetricName.String(),
		Help: "Requests per pool",
	},
		[]string{"zone", "account", "load_balancer_name", "pool_name", "origin_name"},
	)

	logpushFailedJobsAccount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cloudflare_logpush_failed_jobs_account_count",
		Help: "Number of failed logpush jobs on the account level",
	},
		[]string{"account", "account_name", "account_type", "destination", "job_id", "final"},
	)

	logpushFailedJobsZone = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: logpushFailedJobsZoneMetricName.String(),
		Help: "Number of failed logpush jobs on the zone level",
	},
		[]string{"destination", "job_id", "final"},
	)

	// added

	zoneCustomerError4xx = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneCustomerError4xxRate.String(),
		Help: "Number of error rates of 4xx",
	}, []string{"zone", "account", "status", "country", "host"},
	)

	zoneCustomerError5xx = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneCustomerError5xxRate.String(),
		Help: "Number of error rates of 5xx",
	}, []string{"zone", "account", "status", "country", "host"},
	)

	zoneEdgeError = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: zoneEdgeErrorRate.String(),
		Help: "Number of error rate of 4xx and 5xx",
	}, []string{"zone", "account", "status", "country", "host"},
	)

	zoneOriginError = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneOriginErrorRate.String(),
		Help: "Number of error rates of 4xx and 5xx in HTTP requests",
	}, []string{"zone", "account", "status", "country", "host"},
	)

	zoneBotRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneBotRequestsByCountry.String(),
		Help: "Number of bot requests over country",
	}, []string{"zone", "account", "country", "action", "rule", "host"},
	)

	zoneCacheHit = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: zoneCacheHitRatio.String(),
		Help: "Number fo cache hit ratio",
	}, []string{"zone", "account", "cachedRequests", "requests"},
	)

	zoneHealthCheckEventsAvg = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: zoneHealthCheckEventsAdaptiveGroupsAvg.String(),
		Help: "Number fo cache hit ratio",
	}, []string{"zone", "account"},
	)

	zoneFirewallBotsDetected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneFirewallBotsDetectedSource.String(),
		Help: "Number of bot requests over country",
	}, []string{"zone", "account", "source", "action", "rule", "host"},
	)

	zoneFirewallAction = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneFirewallRequestAction.String(),
		Help: "Number of Firewall events",
	}, []string{"zone", "account", "action"},
	)

	zoneRequestMethod = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: zoneRequestMethodCount.String(),
		Help: "Number of zone request method",
	}, []string{"zone", "account", "method"},
	)
	magicTransitActiveTunnel = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: magicTransitActiveTunnels.String(),
			Help: "Number of active Magic Transit tunnels",
		},
		[]string{"account", "account_name", "account_type"},
	)
	magicTransitHealthyTunnel = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: magicTransitHealthyTunnels.String(),
			Help: "Number of healthy Magic Transit tunnels",
		},
		[]string{"account", "account_name", "account_type"},
	)
	magicTransitTunnelFailure = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: magicTransitTunnelFailures.String(),
			Help: "Number of failed Magic Transit tunnels",
		},
		[]string{"account", "account_name", "account_type"},
	)
	magicTransitEdgeColo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: magicTransitEdgeColoCount.String(),
			Help: "Number of edge colocation sites involved in Magic Transit tunnels",
		},
		[]string{"account", "account_name", "account_type"},
	)

	zoneCertificateValidation = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: zoneCertificateValidationStatus.String(),
			Help: "SSL certificate status for a given zone",
		},
		[]string{"zone_id", "zone_name", "status", "issuer"},
	)
)

// BuildAllMetricsSet helps to build all metric and return as Set.
func BuildAllMetricsSet() Set {
	allMetricsSet := Set{}
	allMetricsSet.Add(zoneRequestTotalMetricName)
	allMetricsSet.Add(zoneRequestCachedMetricName)
	allMetricsSet.Add(zoneRequestSSLEncryptedMetricName)
	allMetricsSet.Add(zoneRequestContentTypeMetricName)
	allMetricsSet.Add(zoneRequestCountryMetricName)
	allMetricsSet.Add(zoneRequestHTTPStatusMetricName)
	allMetricsSet.Add(zoneRequestBrowserMapMetricName)
	allMetricsSet.Add(zoneRequestOriginStatusCountryHostMetricName)
	allMetricsSet.Add(zoneRequestStatusCountryHostMetricName)
	allMetricsSet.Add(zoneBandwidthTotalMetricName)
	allMetricsSet.Add(zoneBandwidthCachedMetricName)
	allMetricsSet.Add(zoneBandwidthSSLEncryptedMetricName)
	allMetricsSet.Add(zoneBandwidthContentTypeMetricName)
	allMetricsSet.Add(zoneBandwidthCountryMetricName)
	allMetricsSet.Add(zoneThreatsTotalMetricName)
	allMetricsSet.Add(zoneThreatsCountryMetricName)
	allMetricsSet.Add(zoneThreatsTypeMetricName)
	allMetricsSet.Add(zonePageviewsTotalMetricName)
	allMetricsSet.Add(zoneUniquesTotalMetricName)
	allMetricsSet.Add(zoneColocationVisitsMetricName)
	allMetricsSet.Add(zoneColocationEdgeResponseBytesMetricName)
	allMetricsSet.Add(zoneColocationRequestsTotalMetricName)
	allMetricsSet.Add(zoneFirewallEventsCountMetricName)
	allMetricsSet.Add(zoneHealthCheckEventsOriginCountMetricName)
	allMetricsSet.Add(workerRequestsMetricName)
	allMetricsSet.Add(workerErrorsMetricName)
	allMetricsSet.Add(workerCPUTimeMetricName)
	allMetricsSet.Add(workerDurationMetricName)
	allMetricsSet.Add(poolHealthStatusMetricName)
	allMetricsSet.Add(poolRequestsTotalMetricName)
	allMetricsSet.Add(logpushFailedJobsAccountMetricName)
	allMetricsSet.Add(logpushFailedJobsZoneMetricName)
	// new
	allMetricsSet.Add(zoneCustomerError4xxRate)
	allMetricsSet.Add(zoneCustomerError5xxRate)
	allMetricsSet.Add(zoneEdgeErrorRate)
	allMetricsSet.Add(zoneOriginErrorRate)
	allMetricsSet.Add(zoneBotRequestsByCountry)
	allMetricsSet.Add(zoneHealthCheckEventsAdaptiveGroupsAvg)
	allMetricsSet.Add(zoneFirewallBotsDetectedSource)
	allMetricsSet.Add(zoneFirewallRequestAction)
	allMetricsSet.Add(zoneRequestMethodCount)
	allMetricsSet.Add(magicTransitActiveTunnels)
	allMetricsSet.Add(magicTransitEdgeColoCount)
	allMetricsSet.Add(magicTransitHealthyTunnels)
	allMetricsSet.Add(magicTransitTunnelFailures)
	allMetricsSet.Add(zoneCertificateValidationStatus)

	return allMetricsSet
}

// BuildDeniedMetricsSet returns Set and error.
func BuildDeniedMetricsSet(metricsDenylist []string) (Set, error) {
	deniedMetricsSet := Set{}
	allMetricsSet := BuildAllMetricsSet()
	for _, metric := range metricsDenylist {
		if !allMetricsSet.Has(MetricName(metric)) {
			return nil, fmt.Errorf("metric %s doesn't exists", metric)
		}
		deniedMetricsSet.Add(MetricName(metric))
	}
	return deniedMetricsSet, nil
}

// MustRegisterMetrics register the metrics.
func MustRegisterMetrics(deniedMetrics Set) {
	if !deniedMetrics.Has(zoneRequestTotalMetricName) {
		prometheus.MustRegister(zoneRequestTotal)
	}
	if !deniedMetrics.Has(zoneRequestCachedMetricName) {
		prometheus.MustRegister(zoneRequestCached)
	}
	if !deniedMetrics.Has(zoneRequestSSLEncryptedMetricName) {
		prometheus.MustRegister(zoneRequestSSLEncrypted)
	}
	if !deniedMetrics.Has(zoneRequestContentTypeMetricName) {
		prometheus.MustRegister(zoneRequestContentType)
	}
	if !deniedMetrics.Has(zoneRequestCountryMetricName) {
		prometheus.MustRegister(zoneRequestCountry)
	}
	if !deniedMetrics.Has(zoneRequestHTTPStatusMetricName) {
		prometheus.MustRegister(zoneRequestHTTPStatus)
	}
	if !deniedMetrics.Has(zoneRequestBrowserMapMetricName) {
		prometheus.MustRegister(zoneRequestBrowserMap)
	}
	if !deniedMetrics.Has(zoneRequestOriginStatusCountryHostMetricName) {
		prometheus.MustRegister(zoneRequestOriginStatusCountryHost)
	}
	if !deniedMetrics.Has(zoneRequestStatusCountryHostMetricName) {
		prometheus.MustRegister(zoneRequestStatusCountryHost)
	}
	if !deniedMetrics.Has(zoneBandwidthTotalMetricName) {
		prometheus.MustRegister(zoneBandwidthTotal)
	}
	if !deniedMetrics.Has(zoneBandwidthCachedMetricName) {
		prometheus.MustRegister(zoneBandwidthCached)
	}
	if !deniedMetrics.Has(zoneBandwidthSSLEncryptedMetricName) {
		prometheus.MustRegister(zoneBandwidthSSLEncrypted)
	}
	if !deniedMetrics.Has(zoneBandwidthContentTypeMetricName) {
		prometheus.MustRegister(zoneBandwidthContentType)
	}
	if !deniedMetrics.Has(zoneBandwidthCountryMetricName) {
		prometheus.MustRegister(zoneBandwidthCountry)
	}
	if !deniedMetrics.Has(zoneThreatsTotalMetricName) {
		prometheus.MustRegister(zoneThreatsTotal)
	}
	if !deniedMetrics.Has(zoneThreatsCountryMetricName) {
		prometheus.MustRegister(zoneThreatsCountry)
	}
	if !deniedMetrics.Has(zoneThreatsTypeMetricName) {
		prometheus.MustRegister(zoneThreatsType)
	}
	if !deniedMetrics.Has(zonePageviewsTotalMetricName) {
		prometheus.MustRegister(zonePageviewsTotal)
	}
	if !deniedMetrics.Has(zoneUniquesTotalMetricName) {
		prometheus.MustRegister(zoneUniquesTotal)
	}
	if !deniedMetrics.Has(zoneColocationVisitsMetricName) {
		prometheus.MustRegister(zoneColocationVisits)
	}
	if !deniedMetrics.Has(zoneColocationEdgeResponseBytesMetricName) {
		prometheus.MustRegister(zoneColocationEdgeResponseBytes)
	}
	if !deniedMetrics.Has(zoneColocationRequestsTotalMetricName) {
		prometheus.MustRegister(zoneColocationRequestsTotal)
	}
	if !deniedMetrics.Has(zoneFirewallEventsCountMetricName) {
		prometheus.MustRegister(zoneFirewallEventsCount)
	}
	if !deniedMetrics.Has(zoneHealthCheckEventsOriginCountMetricName) {
		prometheus.MustRegister(zoneHealthCheckEventsOriginCount)
	}
	if !deniedMetrics.Has(workerRequestsMetricName) {
		prometheus.MustRegister(workerRequests)
	}
	if !deniedMetrics.Has(workerErrorsMetricName) {
		prometheus.MustRegister(workerErrors)
	}
	if !deniedMetrics.Has(workerCPUTimeMetricName) {
		prometheus.MustRegister(workerCPUTime)
	}
	if !deniedMetrics.Has(workerDurationMetricName) {
		prometheus.MustRegister(workerDuration)
	}
	if !deniedMetrics.Has(poolHealthStatusMetricName) {
		prometheus.MustRegister(poolHealthStatus)
	}
	if !deniedMetrics.Has(poolRequestsTotalMetricName) {
		prometheus.MustRegister(poolRequestsTotal)
	}
	if !deniedMetrics.Has(logpushFailedJobsAccountMetricName) {
		prometheus.MustRegister(logpushFailedJobsAccount)
	}
	if !deniedMetrics.Has(logpushFailedJobsZoneMetricName) {
		prometheus.MustRegister(logpushFailedJobsZone)
	}
	// new
	if !deniedMetrics.Has(zoneCustomerError4xxRate) {
		prometheus.MustRegister(zoneCustomerError4xx)
	}
	if !deniedMetrics.Has(zoneCustomerError5xxRate) {
		prometheus.MustRegister(zoneCustomerError5xx)
	}
	if !deniedMetrics.Has(zoneEdgeErrorRate) {
		prometheus.MustRegister(zoneEdgeError)
	}
	if !deniedMetrics.Has(zoneOriginErrorRate) {
		prometheus.MustRegister(zoneOriginError)
	}
	if !deniedMetrics.Has(zoneBotRequestsByCountry) {
		prometheus.MustRegister(zoneBotRequests)
	}
	if !deniedMetrics.Has(zoneCacheHitRatio) {
		prometheus.MustRegister(zoneCacheHit)
	}
	if !deniedMetrics.Has(zoneHealthCheckEventsAdaptiveGroupsAvg) {
		prometheus.MustRegister(zoneHealthCheckEventsAvg)
	}
	if !deniedMetrics.Has(zoneFirewallBotsDetectedSource) {
		prometheus.MustRegister(zoneFirewallBotsDetected)
	}
	if !deniedMetrics.Has(zoneFirewallRequestAction) {
		prometheus.MustRegister(zoneFirewallAction)
	}
	if !deniedMetrics.Has(zoneRequestMethodCount) {
		prometheus.MustRegister(zoneRequestMethod)
	}
	if !deniedMetrics.Has(magicTransitActiveTunnels) {
		prometheus.MustRegister(magicTransitActiveTunnel)
	}
	if !deniedMetrics.Has(magicTransitEdgeColoCount) {
		prometheus.MustRegister(magicTransitEdgeColo)
	}
	if !deniedMetrics.Has(magicTransitHealthyTunnels) {
		prometheus.MustRegister(magicTransitHealthyTunnel)
	}
	if !deniedMetrics.Has(magicTransitTunnelFailures) {
		prometheus.MustRegister(magicTransitTunnelFailure)
	}
	if !deniedMetrics.Has(zoneCertificateValidationStatus) {
		prometheus.MustRegister(zoneCertificateValidation)
	}
}

// FetchWorkerAnalytics handles cloudflare account and expose metrics like requests, error, Worker CPUTime and Duration.
func FetchWorkerAnalytics(account cloudflare.Account, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	// Replace spaces with hyphens and convert to lowercase
	accountName := strings.ToLower(strings.ReplaceAll(account.Name, " ", "-"))

	// Initialize default values for metrics
	initializeDefaultMetrics(accountName, "unknown")

	r, err := cloudflareAPI.FetchWorkerTotals(account.ID)
	if err != nil {
		// Return early if API call fails, keeping default metrics
		return
	}

	for _, a := range r.Viewer.Accounts {
		if len(a.WorkersInvocationsAdaptive) == 0 {
			// Ensure metrics for "unknown" are set when no worker data is present
			initializeDefaultMetrics(accountName, "unknown")
			continue
		}

		for _, w := range a.WorkersInvocationsAdaptive {
			// Add actual metrics
			workerRequests.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName}).Add(float64(w.Sum.Requests))
			workerErrors.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName}).Add(float64(w.Sum.Errors))
			workerCPUTime.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "quantile": "P50"}).Set(float64(w.Quantiles.CPUTimeP50))
			workerCPUTime.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "quantile": "P75"}).Set(float64(w.Quantiles.CPUTimeP75))
			workerCPUTime.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "quantile": "P99"}).Set(float64(w.Quantiles.CPUTimeP99))
			workerCPUTime.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "quantile": "P999"}).Set(float64(w.Quantiles.CPUTimeP999))
			workerDuration.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "quantile": "P50"}).Set(math.Round(float64(w.Quantiles.DurationP50)*1000) / 1000)
			workerDuration.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "quantile": "P75"}).Set(math.Round(float64(w.Quantiles.DurationP75)*1000) / 1000)
			workerDuration.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "quantile": "P99"}).Set(math.Round(float64(w.Quantiles.DurationP99)*1000) / 1000)
			workerDuration.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "quantile": "P999"}).Set(math.Round(float64(w.Quantiles.DurationP999)*1000) / 1000)
		}
	}
}

// Helper function to initialize default metrics for a script
func initializeDefaultMetrics(accountName, scriptName string) {
	workerRequests.With(prometheus.Labels{"script_name": scriptName, "account": accountName}).Add(0)
	workerErrors.With(prometheus.Labels{"script_name": scriptName, "account": accountName}).Add(0)
	for _, quantile := range []string{"P50", "P75", "P99", "P999"} {
		workerCPUTime.With(prometheus.Labels{"script_name": scriptName, "account": accountName, "quantile": quantile}).Set(0)
		workerDuration.With(prometheus.Labels{"script_name": scriptName, "account": accountName, "quantile": quantile}).Set(0)
	}
}

// filterZones helper function to filter the zones.
func filterZones(all []cloudflare.Zone, target []string) []cloudflare.Zone {
	var filtered []cloudflare.Zone

	if (len(target)) == 0 {
		return all
	}

	for _, tz := range target {
		for _, z := range all {
			if tz == z.ID {
				filtered = append(filtered, z)
				logging.Info("Filtering zone: ", z.ID, " ", z.Name)
			}
		}
	}
	return filtered
}

// getTargetZones helper function to get targeted zones.
func getTargetZones() []string {
	var zoneIDs []string
	if len(viper.GetString("cf_zones")) > 0 {
		zoneIDs = strings.Split(viper.GetString("cf_zones"), ",")
	} else {
		// deprecated
		for _, e := range os.Environ() {
			if strings.HasPrefix(e, "ZONE_") {
				split := strings.SplitN(e, "=", 2)
				zoneIDs = append(zoneIDs, split[1])
			}
		}
	}
	return zoneIDs
}

// getExcludedZones returns array of excluded zones.
func getExcludedZones() []string {
	var zoneIDs []string

	if len(viper.GetString("cf_exclude_zones")) > 0 {
		zoneIDs = strings.Split(viper.GetString("cf_exclude_zones"), ",")
	}
	return zoneIDs
}

func allZonesAreEmpty(account []models.LogpushResponse) bool {
	// Check if all zones are empty
	for _, zone := range account {
		if len(zone.LogpushHealthAdaptiveGroups) > 0 {
			return false
		}
	}
	return true // All zones are empty
}

// fetchLogpushAnalyticsForAccount expose metrics related to logpush.
func fetchLogpushAnalyticsForAccount(account cloudflare.Account, wg *sync.WaitGroup) {
	defer wg.Done()

	defer func() { // Panic Recovery
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in fetchLogpushAnalyticsForAccount: %v", r)
		}
	}()

	r, err := cloudflareAPI.FetchLogpushAccount(account.ID)
	if err != nil {
		// Add default values for the metrics in case of an API failure
		logpushFailedJobsAccount.With(prometheus.Labels{
			"account":      account.ID,
			"account_name": account.Name,
			"account_type": account.Type,
			"destination":  "unknown",
			"job_id":       "unknown",
			"final":        "unknown",
		}).Add(0)
		return
	}

	if r == nil || r.Viewer.Accounts == nil {
		return
	}

	// Check if the API response is empty and handle accordingly
	if len(r.Viewer.Accounts) == 0 || allZonesAreEmpty(r.Viewer.Accounts) {
		logpushFailedJobsAccount.With(prometheus.Labels{
			"account":      account.ID,
			"account_name": account.Name,
			"account_type": account.Type,
			"destination":  "unknown",
			"job_id":       "unknown",
			"final":        "unknown",
		}).Add(0)
		return
	}

	// Process metrics from the API response
	for _, acc := range r.Viewer.Accounts {
		for _, LogpushHealthAdaptiveGroup := range acc.LogpushHealthAdaptiveGroups {
			logpushFailedJobsAccount.With(prometheus.Labels{
				"account":      account.ID,
				"account_name": account.Name,
				"account_type": account.Type,
				"destination":  LogpushHealthAdaptiveGroup.Dimensions.DestinationType,
				"job_id":       strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.JobID),
				"final":        strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.Final),
			}).Add(float64(LogpushHealthAdaptiveGroup.Count))
		}
	}
}

func fetchMagicTransitHealth(account cloudflare.Account, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	// Fetch data from the Magic Transit API
	r, err := cloudflareAPI.MagicTransitTunnelHealthChecksAdaptiveGroups(account.ID)
	if err != nil {
		// Add default values for metrics in case of API failure
		magicTransitActiveTunnel.With(prometheus.Labels{"account": account.ID, "account_name": account.Name, "account_type": account.Type}).Set(0)
		magicTransitHealthyTunnel.With(prometheus.Labels{"account": account.ID, "account_name": account.Name, "account_type": account.Type}).Set(0)
		magicTransitTunnelFailure.With(prometheus.Labels{"account": account.ID, "account_name": account.Name, "account_type": account.Type}).Set(0)
		magicTransitEdgeColo.With(prometheus.Labels{"account": account.ID, "account_name": account.Name, "account_type": account.Type}).Set(0)
		return
	}

	// Check if the API response is empty and handle accordingly
	if len(r.Viewer.Accounts) == 0 {
		magicTransitActiveTunnel.With(prometheus.Labels{"account": account.ID, "account_name": account.Name, "account_type": account.Type}).Set(0)
		magicTransitHealthyTunnel.With(prometheus.Labels{"account": account.ID, "account_name": account.Name, "account_type": account.Type}).Set(0)
		magicTransitTunnelFailure.With(prometheus.Labels{"account": account.ID, "account_name": account.Name, "account_type": account.Type}).Set(0)
		magicTransitEdgeColo.With(prometheus.Labels{"account": account.ID, "account_name": account.Name, "account_type": account.Type}).Set(0)
		return
	}

	// Initialize metrics
	var activeTunnels, healthyTunnels, tunnelFailures, edgeColoCount float64

	// Process metrics from the API response
	for _, acc := range r.Viewer.Accounts {
		for _, group := range acc.MagicTransitTunnelHealthChecksAdaptiveGroups {
			if group.Dimensions.Active == 1 {
				activeTunnels++
			}
			if group.Dimensions.ResultStatus == "healthy" {
				healthyTunnels++
			} else {
				tunnelFailures++
			}
			if group.Dimensions.EdgePopName != "" {
				edgeColoCount++
			}
		}
	}

	// Set Prometheus metrics
	magicTransitActiveTunnel.With(prometheus.Labels{"account": account.ID, "account_name": account.Name, "account_type": account.Type}).Set(activeTunnels)
	magicTransitHealthyTunnel.With(prometheus.Labels{"account": account.ID, "account_name": account.Name, "account_type": account.Type}).Set(healthyTunnels)
	magicTransitTunnelFailure.With(prometheus.Labels{"account": account.ID, "account_name": account.Name, "account_type": account.Type}).Set(tunnelFailures)
	magicTransitEdgeColo.With(prometheus.Labels{"account": account.ID, "account_name": account.Name, "account_type": account.Type}).Set(edgeColoCount)
}

func filterNonFreePlanZones(zones []cloudflare.Zone) (filteredZones []cloudflare.Zone) {

	for _, z := range zones {
		if z.Plan.ZonePlanCommon.ID != "0feeeeeeeeeeeeeeeeeeeeeeeeeeeeee" {
			filteredZones = append(filteredZones, z)
		}
	}

	return
}

func findZoneAccountName(zones []cloudflare.Zone, ID string) (string, string) {

	for _, z := range zones {

		if strings.TrimSpace(z.ID) == strings.TrimSpace(ID) {

			return z.Name, strings.ToLower(strings.ReplaceAll(z.Account.Name, " ", "-"))
		}
	}

	return "", ""
}

func fetchZoneAnalytics(zones []cloudflare.Zone, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	// None of the below referenced metrics are available in the free tier
	if viper.GetBool("free_tier") {
		return
	}

	zoneIDs := cloudflareAPI.ExtractZoneIDs(filterNonFreePlanZones(zones))
	if len(zoneIDs) == 0 {
		return
	}

	r, err := cloudflareAPI.FetchZoneTotals(zoneIDs)
	if err != nil {
		return
	}

	for _, z := range r.Viewer.Zones {
		name, account := findZoneAccountName(zones, z.ZoneTag)
		currentZone := z

		addHTTPGroups(&currentZone, name, account)
		addFirewallGroups(&currentZone, name, account)
		addHealthCheckGroups(&currentZone, name, account)
		addHTTPAdaptiveGroups(&currentZone, name, account)
	}
}

func addHTTPGroups(z *models.ZoneResp, name string, account string) {

	// Initialize metrics with default values
	zoneRequestTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(0)
	zoneRequestCached.With(prometheus.Labels{"zone": name, "account": account}).Add(0)
	zoneRequestSSLEncrypted.With(prometheus.Labels{"zone": name, "account": account}).Add(0)
	zoneBandwidthTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(0)
	zoneBandwidthCached.With(prometheus.Labels{"zone": name, "account": account}).Add(0)
	zoneBandwidthSSLEncrypted.With(prometheus.Labels{"zone": name, "account": account}).Add(0)
	zoneThreatsTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(0)
	zonePageviewsTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(0)
	zoneUniquesTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(0)

	// Initialize multi-dimensional metrics with default labels
	zoneRequestContentType.With(prometheus.Labels{"zone": name, "account": account, "content_type": "unknown"}).Add(0)
	zoneBandwidthContentType.With(prometheus.Labels{"zone": name, "account": account, "content_type": "unknown"}).Add(0)
	zoneRequestCountry.With(prometheus.Labels{"zone": name, "account": account, "country": "unknown", "region": "unknown"}).Add(0)
	zoneBandwidthCountry.With(prometheus.Labels{"zone": name, "account": account, "country": "unknown", "region": "unknown"}).Add(0)
	zoneThreatsCountry.With(prometheus.Labels{"zone": name, "account": account, "country": "unknown", "region": "unknown"}).Add(0)
	zoneRequestHTTPStatus.With(prometheus.Labels{"zone": name, "account": account, "status": "unknown"}).Add(0)
	zoneRequestBrowserMap.With(prometheus.Labels{"zone": name, "account": account, "family": "unknown"}).Add(0)
	zoneThreatsType.With(prometheus.Labels{"zone": name, "account": account, "type": "unknown"}).Add(0)
	zoneCacheHit.With(
		prometheus.Labels{
			"zone":           name,
			"account":        account,
			"requests":       "",
			"cachedRequests": "",
		}).Set(0)

	zoneRequestMethod.With(prometheus.Labels{
		"zone":    name,
		"account": account,
		"method":  "", // The HTTP method dimension
	}).Add(0)

	// Nothing to do if HTTP1mGroups is empty
	if len(z.HTTP1mGroups) == 0 {
		return
	}

	zt := z.HTTP1mGroups[0]

	// Update metrics with actual data
	zoneRequestTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.Requests))
	zoneRequestCached.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.CachedRequests))
	zoneRequestSSLEncrypted.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.EncryptedRequests))

	for _, ct := range zt.Sum.ContentType {
		zoneRequestContentType.With(prometheus.Labels{"zone": name, "account": account, "content_type": ct.EdgeResponseContentType}).Add(float64(ct.Requests))
		zoneBandwidthContentType.With(prometheus.Labels{"zone": name, "account": account, "content_type": ct.EdgeResponseContentType}).Add(float64(ct.Bytes))
	}

	for _, country := range zt.Sum.Country {
		c := countries.ByName(country.ClientCountryName)
		region := c.Info().Region.Info().Name

		zoneRequestCountry.With(prometheus.Labels{"zone": name, "account": account, "country": country.ClientCountryName, "region": region}).Add(float64(country.Requests))
		zoneBandwidthCountry.With(prometheus.Labels{"zone": name, "account": account, "country": country.ClientCountryName, "region": region}).Add(float64(country.Bytes))
		zoneThreatsCountry.With(prometheus.Labels{"zone": name, "account": account, "country": country.ClientCountryName, "region": region}).Add(float64(country.Threats))
	}

	for _, status := range zt.Sum.ResponseStatus {
		zoneRequestHTTPStatus.With(prometheus.Labels{"zone": name, "account": account, "status": strconv.Itoa(status.EdgeResponseStatus)}).Add(float64(status.Requests))
	}

	for _, browser := range zt.Sum.BrowserMap {
		zoneRequestBrowserMap.With(prometheus.Labels{"zone": name, "account": account, "family": browser.UaBrowserFamily}).Add(float64(browser.PageViews))
	}

	zoneBandwidthTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.Bytes))
	zoneBandwidthCached.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.CachedBytes))
	zoneBandwidthSSLEncrypted.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.EncryptedBytes))

	zoneThreatsTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.Threats))

	for _, t := range zt.Sum.ThreatPathing {
		zoneThreatsType.With(prometheus.Labels{"zone": name, "account": account, "type": t.Name}).Add(float64(t.Requests))
	}

	zonePageviewsTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.PageViews))

	// Uniques
	zoneUniquesTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Unique.Uniques))

	zoneCacheHit.With(
		prometheus.Labels{
			"zone":           name,
			"account":        account,
			"requests":       strconv.FormatUint(zt.Sum.Requests, 10),
			"cachedRequests": strconv.FormatUint(zt.Sum.CachedRequests, 10),
		}).Set(float64(zt.Sum.CachedRequests) / float64(zt.Sum.Requests))

	// Map to track HTTP method counts
	methodCounts := make(map[string]float64)

	// Loop through firewall events
	for _, g := range z.FirewallEventsAdaptiveGroups {
		// Extract ClientRequestHTTPHost or other dimensions
		httpMethod := g.Dimensions.ClientRequestHTTPHost // Adjust based on available data

		// Increment the count for this HTTP method
		methodCounts[httpMethod] += float64(g.Count)
	}

	// Push metrics to Prometheus
	for method, count := range methodCounts {
		zoneRequestMethod.With(prometheus.Labels{
			"zone":    name,
			"account": account,
			"method":  method, // The HTTP method dimension
		}).Add(count)
	}
}

func normalizeRuleName(initialText string) string {
	maxLength := 200
	nonSpaceName := strings.ReplaceAll(strings.ToLower(initialText), " ", "_")
	if len(nonSpaceName) > maxLength {
		return nonSpaceName[:maxLength]
	}
	return nonSpaceName
}

func addFirewallGroups(z *models.ZoneResp, name string, account string) {

	zoneFirewallAction.With(
		prometheus.Labels{
			"zone":    name,
			"account": account,
			"action":  "unknown",
		}).Add(0)

	// Initialize metrics with default values
	zoneFirewallEventsCount.With(
		prometheus.Labels{
			"zone":    name,
			"account": account,
		}).Add(0)

	// Initialize metrics with default values
	zoneBotRequests.With(
		prometheus.Labels{
			"zone":    name,
			"account": account,
			"country": "",
			"action":  "",
			"rule":    "",
			"host":    "",
		}).Add(0)

	zoneFirewallBotsDetected.With(
		prometheus.Labels{
			"zone":    name,
			"account": account,
			"source":  "",
			"action":  "",
			"rule":    "",
			"host":    "",
		}).Add(0)

	// Nothing to do if there are no FirewallEventsAdaptiveGroups
	if len(z.FirewallEventsAdaptiveGroups) == 0 {
		return
	}

	// Fetch firewall rules map
	rulesMap := cloudflareAPI.FetchFirewallRules(z.ZoneTag)

	// Process each firewall event group
	for _, g := range z.FirewallEventsAdaptiveGroups {
		zoneFirewallEventsCount.With(
			prometheus.Labels{
				"zone":    name,
				"account": account,
			}).Add(float64(g.Count))

		zoneFirewallAction.With(
			prometheus.Labels{
				"zone":    name,
				"account": account,
				"action":  g.Dimensions.Action,
			}).Add(float64(g.Count))

		zoneBotRequests.With(
			prometheus.Labels{
				"zone":    name,
				"account": account,
				"country": g.Dimensions.ClientCountryName,
				"action":  g.Dimensions.Action,
				"rule":    normalizeRuleName(rulesMap[g.Dimensions.RuleID]),
				"host":    g.Dimensions.ClientRequestHTTPHost,
			}).Add(float64(g.Count))

		zoneFirewallBotsDetected.With(
			prometheus.Labels{
				"zone":    name,
				"account": account,
				"source":  g.Dimensions.Source,
				"action":  g.Dimensions.Action,
				"rule":    normalizeRuleName(rulesMap[g.Dimensions.RuleID]),
				"host":    g.Dimensions.ClientRequestHTTPHost,
			}).Add(float64(g.Count))

	}

}

func addHealthCheckGroups(z *models.ZoneResp, name string, account string) {

	// Initialize metrics with default values
	zoneHealthCheckEventsOriginCount.With(
		prometheus.Labels{
			"zone":          name,
			"account":       account,
			"health_status": "unknown",
			"origin_ip":     "unknown",
			"region":        "unknown",
			"fqdn":          "unknown",
		}).Add(0)

	zoneHealthCheckEventsAvg.With(
		prometheus.Labels{
			"zone":    name,
			"account": account,
		}).Set(0)

	// Nothing to do if there are no HealthCheckEventsAdaptiveGroups
	if len(z.HealthCheckEventsAdaptiveGroups) == 0 {
		return
	}

	var totalEvents uint64
	var totalCount int

	// Process each health check event group
	for _, g := range z.HealthCheckEventsAdaptiveGroups {
		// Add the count of events to the total
		totalEvents += g.Count
		totalCount++

		zoneHealthCheckEventsOriginCount.With(
			prometheus.Labels{
				"zone":          name,
				"account":       account,
				"health_status": g.Dimensions.HealthStatus,
				"origin_ip":     g.Dimensions.OriginIP,
				"region":        g.Dimensions.Region,
				"fqdn":          g.Dimensions.Fqdn,
			}).Add(float64(g.Count))
	}

	// Calculate the average health check events
	var avgHealthCheckEvents float64
	if totalCount > 0 {
		avgHealthCheckEvents = float64(totalEvents) / float64(totalCount)
	}

	zoneHealthCheckEventsAvg.With(
		prometheus.Labels{
			"zone":    name,
			"account": account,
		}).Set(avgHealthCheckEvents)
}

func addHTTPAdaptiveGroups(z *models.ZoneResp, name string, account string) {
	// Initialize default values for `zoneRequestOriginStatusCountryHost`
	zoneRequestOriginStatusCountryHost.With(
		prometheus.Labels{
			"zone":    name,
			"account": account,
			"status":  "unknown",
			"country": "unknown",
			"host":    "unknown",
		}).Add(0)

	// Initialize default values for `zoneOriginError`
	zoneOriginError.With(
		prometheus.Labels{
			"zone":    name,
			"account": account,
			"status":  "unknown",
			"country": "unknown",
			"host":    "unknown",
		}).Add(0)

	// Initialize default values for `zoneRequestStatusCountryHost`
	zoneRequestStatusCountryHost.With(
		prometheus.Labels{
			"zone":    name,
			"account": account,
			"status":  "unknown",
			"country": "unknown",
			"host":    "unknown",
		}).Add(0)

	// Initialize default values for `zoneCustomerError4xx`
	zoneCustomerError4xx.With(
		prometheus.Labels{
			"zone":    name,
			"account": account,
			"status":  "unknown",
			"country": "unknown",
			"host":    "unknown",
		}).Add(0)

	// Initialize default values for `zoneCustomerError5xx`
	zoneCustomerError5xx.With(
		prometheus.Labels{
			"zone":    name,
			"account": account,
			"status":  "unknown",
			"country": "unknown",
			"host":    "unknown",
		}).Add(0)

	// Initialize default values for `zoneCustomerError5xx`
	zoneEdgeError.With(
		prometheus.Labels{
			"zone":    name,
			"account": account,
			"status":  "unknown",
			"country": "unknown",
			"host":    "unknown",
		}).Add(0)

	// Process `HTTPRequestsAdaptiveGroups`
	for _, g := range z.HTTPRequestsAdaptiveGroups {
		zoneRequestOriginStatusCountryHost.With(
			prometheus.Labels{
				"zone":    name,
				"account": account,
				"status":  strconv.Itoa(int(g.Dimensions.OriginResponseStatus)),
				"country": g.Dimensions.ClientCountryName,
				"host":    g.Dimensions.ClientRequestHTTPHost,
			}).Add(float64(g.Count))
	}

	// Process `HTTPRequestsAdaptiveGroups`
	for _, g := range z.HTTPRequestsAdaptiveGroups {

		status := g.Dimensions.OriginResponseStatus // Get the origin response status

		if (status >= 400 && status < 500) || (status >= 500 && status < 600) {
		}
		zoneOriginError.With(
			prometheus.Labels{
				"zone":    name,
				"account": account,
				"status":  strconv.Itoa(int(g.Dimensions.OriginResponseStatus)),
				"country": g.Dimensions.ClientCountryName,
				"host":    g.Dimensions.ClientRequestHTTPHost,
			}).Add(float64(g.Count))

	}

	// Process `HTTPRequestsEdgeCountryHost` for OriginResponseStatus
	for _, g := range z.HTTPRequestsEdgeCountryHost {

		zoneRequestStatusCountryHost.With(
			prometheus.Labels{
				"zone":    name,
				"account": account,
				"status":  strconv.Itoa(int(g.Dimensions.EdgeResponseStatus)),
				"country": g.Dimensions.ClientCountryName,
				"host":    g.Dimensions.ClientRequestHTTPHost,
			}).Add(float64(g.Count))
	}

	// Process `HTTPRequestsEdgeCountryHost` and EdgeResponseStatus for 4xx
	for _, g := range z.HTTPRequestsEdgeCountryHost {
		statusCode := g.Dimensions.EdgeResponseStatus

		// Check if the status code is a 4xx error
		if statusCode >= 400 && statusCode < 500 {
			// Increment the Prometheus metric for 4xx errors
			zoneCustomerError4xx.With(
				prometheus.Labels{
					"zone":    name,
					"account": account,
					"status":  strconv.Itoa(int(g.Dimensions.EdgeResponseStatus)),
					"country": g.Dimensions.ClientCountryName,
					"host":    g.Dimensions.ClientRequestHTTPHost,
				}).Add(float64(g.Count))
		}
	}

	// Process `HTTPRequestsEdgeCountryHost` and EdgeResponseStatus for 5xx
	for _, g := range z.HTTPRequestsEdgeCountryHost {
		statusCode := g.Dimensions.EdgeResponseStatus

		// Check if the status code is a 4xx error
		if statusCode >= 500 {
			// Increment the Prometheus metric for 4xx errors
			zoneCustomerError5xx.With(
				prometheus.Labels{
					"zone":    name,
					"account": account,
					"status":  strconv.Itoa(int(g.Dimensions.EdgeResponseStatus)),
					"country": g.Dimensions.ClientCountryName,
					"host":    g.Dimensions.ClientRequestHTTPHost,
				}).Add(float64(g.Count))
		}
	}

	// Process `HTTPRequestsEdgeCountryHost` and EdgeResponseStatus for 5xx
	for _, g := range z.HTTPRequestsEdgeCountryHost {
		statusCode := g.Dimensions.EdgeResponseStatus

		// Check if the status code is a 4xx error
		if (statusCode >= 400 && statusCode < 500) || (statusCode >= 500 && statusCode < 600) {
			// Increment the Prometheus metric for 4xx errors
			zoneEdgeError.With(
				prometheus.Labels{
					"zone":    name,
					"account": account,
					"status":  strconv.Itoa(int(g.Dimensions.EdgeResponseStatus)),
					"country": g.Dimensions.ClientCountryName,
					"host":    g.Dimensions.ClientRequestHTTPHost,
				}).Inc()
		}
	}

}

func fetchZoneColocationAnalytics(zones []cloudflare.Zone, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	// Colocation metrics are not available in non-enterprise zones
	if viper.GetBool("free_tier") {
		return
	}

	zoneIDs := cloudflareAPI.ExtractZoneIDs(filterNonFreePlanZones(zones))
	if len(zoneIDs) == 0 {
		return
	}

	r, err := cloudflareAPI.FetchColoTotals(zoneIDs)
	if err != nil {
		return
	}
	for _, z := range r.Viewer.Zones {
		cg := z.ColoGroups
		name, account := findZoneAccountName(zones, z.ZoneTag)
		if len(cg) == 0 {
			// Adding default values to ensure visibility in Prometheus
			zoneColocationVisits.With(prometheus.Labels{"zone": name, "account": account, "colocation": "default", "host": "default"}).Add(0)
			zoneColocationEdgeResponseBytes.With(prometheus.Labels{"zone": name, "account": account, "colocation": "default", "host": "default"}).Add(0)
			zoneColocationRequestsTotal.With(prometheus.Labels{"zone": name, "account": account, "colocation": "default", "host": "default"}).Add(0)
			continue
		}
		for _, c := range cg {
			zoneColocationVisits.With(prometheus.Labels{"zone": name, "account": account, "colocation": c.Dimensions.ColoCode, "host": c.Dimensions.Host}).Add(float64(c.Sum.Visits))
			zoneColocationEdgeResponseBytes.With(prometheus.Labels{"zone": name, "account": account, "colocation": c.Dimensions.ColoCode, "host": c.Dimensions.Host}).Add(float64(c.Sum.EdgeResponseBytes))
			zoneColocationRequestsTotal.With(prometheus.Labels{"zone": name, "account": account, "colocation": c.Dimensions.ColoCode, "host": c.Dimensions.Host}).Add(float64(c.Count))
		}
	}
}

func fetchLoadBalancerAnalytics(zones []cloudflare.Zone, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	// None of the below referenced metrics are available in the free tier
	if viper.GetBool("free_tier") {
		return
	}

	zoneIDs := cloudflareAPI.ExtractZoneIDs(filterNonFreePlanZones(zones))
	if len(zoneIDs) == 0 {
		return
	}

	l, err := cloudflareAPI.FetchLoadBalancerTotals(zoneIDs)
	if err != nil {
		return
	}
	for _, lb := range l.Viewer.Zones {
		name, account := findZoneAccountName(zones, lb.ZoneTag)
		lb := lb
		addLoadBalancingRequestsAdaptive(&lb, name, account)
		addLoadBalancingRequestsAdaptiveGroups(&lb, name, account)
	}
}

func addLoadBalancingRequestsAdaptiveGroups(z *models.LbResp, name string, account string) {
	if len(z.LoadBalancingRequestsAdaptiveGroups) == 0 {
		// Default values in case of no data
		poolRequestsTotal.With(
			prometheus.Labels{
				"zone":               name,
				"account":            account,
				"load_balancer_name": "default",
				"pool_name":          "default",
				"origin_name":        "default",
			}).Add(0)
		return
	}
	for _, g := range z.LoadBalancingRequestsAdaptiveGroups {
		poolRequestsTotal.With(
			prometheus.Labels{
				"zone":               name,
				"account":            account,
				"load_balancer_name": g.Dimensions.LbName,
				"pool_name":          g.Dimensions.SelectedPoolName,
				"origin_name":        g.Dimensions.SelectedOriginName,
			}).Add(float64(g.Count))
	}
}

func addLoadBalancingRequestsAdaptive(z *models.LbResp, name string, account string) {
	if len(z.LoadBalancingRequestsAdaptive) == 0 {
		// Default values in case of no data
		poolHealthStatus.With(
			prometheus.Labels{
				"zone":               name,
				"account":            account,
				"load_balancer_name": "default",
				"pool_name":          "default",
			}).Set(0)
		return
	}
	for _, g := range z.LoadBalancingRequestsAdaptive {
		for _, p := range g.Pools {
			poolHealthStatus.With(
				prometheus.Labels{
					"zone":               name,
					"account":            account,
					"load_balancer_name": g.LbName,
					"pool_name":          p.PoolName,
				}).Set(float64(p.Healthy))
		}
	}
}

func fetchLogpushAnalyticsForZone(zones []cloudflare.Zone, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	if viper.GetBool("free_tier") {
		return
	}

	zoneIDs := cloudflareAPI.ExtractZoneIDs(filterNonFreePlanZones(zones))
	if len(zoneIDs) == 0 {
		return
	}

	r, err2 := cloudflareAPI.FetchLogpushZone(zoneIDs)
	if err2 != nil {
		// Add default values for the metrics in case of an API failure
		logpushFailedJobsZone.With(prometheus.Labels{
			"destination": "unknown",
			"job_id":      "unknown",
			"final":       "unknown",
		}).Add(0)
	}

	// Check if the API response is empty and handle accordingly
	if len(r.Viewer.Zones) == 0 || allZonesAreEmpty(r.Viewer.Zones) {
		logpushFailedJobsZone.With(prometheus.Labels{
			"destination": "unknown",
			"job_id":      "unknown",
			"final":       "unknown",
		}).Add(0)
	}

	for _, zone := range r.Viewer.Zones {
		for _, LogpushHealthAdaptiveGroup := range zone.LogpushHealthAdaptiveGroups {
			if LogpushHealthAdaptiveGroup.Count == 0 {
				// Default values in case of no data
				logpushFailedJobsZone.With(prometheus.Labels{
					"destination": LogpushHealthAdaptiveGroup.Dimensions.DestinationType,
					"job_id":      strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.JobID),
					"final":       strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.Final),
				}).Add(0)
			} else {
				logpushFailedJobsZone.With(prometheus.Labels{
					"destination": LogpushHealthAdaptiveGroup.Dimensions.DestinationType,
					"job_id":      strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.JobID),
					"final":       strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.Final),
				}).Add(float64(LogpushHealthAdaptiveGroup.Count))
			}
		}
	}
}

func fetchSSLCertificateStatus(zones []cloudflare.Zone, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	if viper.GetBool("free_tier") {
		return
	}

	zoneIDs := cloudflareAPI.ExtractZoneIDs(filterNonFreePlanZones(zones))
	if len(zoneIDs) == 0 {
		return
	}
	// Fetch SSL certificate status for the zones
	r, err := cloudflareAPI.FetchSSLCertificateStatus(zoneIDs)
	if err != nil {
		logging.Error("Error fetching SSL certificate status: ", err)
		return
	}

	// Loop through the response and create Prometheus metrics
	for _, zone := range r.Result {
		// Example: Extract certificate data
		for _, certificate := range zone.Certificates {
			// Create a label with necessary details
			certificateStatus := certificate.Status // active, expired, etc.

			// Convert the string to a time.Time object
			expiresOnTime, err := time.Parse(time.RFC3339Nano, certificate.ExpiresOn)
			if err != nil {
				log.Fatalf("Error parsing time: %v", err)
			}

			// Convert to Unix timestamp (float64)
			expiresOnTimestamp := float64(expiresOnTime.Unix())

			// Set the value for the metric
			zoneCertificateValidation.With(prometheus.Labels{
				"zone_id":   zone.ZoneID,
				"zone_name": certificate.Hosts[1],
				"status":    certificateStatus,
				"issuer":    certificate.Issuer,
			}).Set(expiresOnTimestamp)
		}
	}
}

// FetchMetrics handle all the functions concurrently to expose metrics.
func FetchMetrics() {
	var wg sync.WaitGroup
	zones := cloudflareAPI.FetchZones()
	accounts := cloudflareAPI.FetchAccounts()
	filteredZones := cloudflareAPI.FilterExcludedZones(filterZones(zones, getTargetZones()), getExcludedZones())

	for _, a := range accounts {
		wg.Add(3) // Add before spawning goroutines
		go FetchWorkerAnalytics(a, &wg)
		go fetchLogpushAnalyticsForAccount(a, &wg)
		go fetchMagicTransitHealth(a, &wg)
	}

	// Make requests in groups of cfgBatchSize to avoid rate limit
	// 10 is the maximum amount of zones you can request at once
	for len(filteredZones) > 0 {
		sliceLength := viper.GetInt("cf_batch_size")
		if len(filteredZones) < viper.GetInt("cf_batch_size") {
			sliceLength = len(filteredZones)
		}

		targetZones := filteredZones[:sliceLength]
		filteredZones = filteredZones[len(targetZones):]

		wg.Add(5) // Add before spawning goroutines
		go fetchZoneAnalytics(targetZones, &wg)
		go fetchZoneColocationAnalytics(targetZones, &wg)
		go fetchLoadBalancerAnalytics(targetZones, &wg)
		go fetchLogpushAnalyticsForZone(targetZones, &wg)
		go fetchSSLCertificateStatus(targetZones, &wg)
	}
	wg.Wait()

}
