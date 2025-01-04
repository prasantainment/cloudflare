package routes

import (
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lablabs/cloudflare-exporter/internal/metrics"
	logging "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// RunExporter starts the metric exporter and serves metrics on the /metrics endpoint
func RunExporter() {

	cfgMetricsPath := viper.GetString("metrics_path")

	if !(len(viper.GetString("cf_api_token")) > 0 || (len(viper.GetString("cf_api_email")) > 0 && len(viper.GetString("cf_api_key")) > 0)) {
		log.Fatal("Please provide CF_API_KEY+CF_API_EMAIL or CF_API_TOKEN")
	}
	if viper.GetInt("cf_batch_size") < 1 || viper.GetInt("cf_batch_size") > 10 {
		log.Fatal("CF_BATCH_SIZE must be between 1 and 10")
	}
	customFormatter := new(logging.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	logging.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

	metricsDenylist := []string{}
	if len(viper.GetString("metrics_denylist")) > 0 {
		metricsDenylist = strings.Split(viper.GetString("metrics_denylist"), ",")
	}
	deniedMetricsSet, err := metrics.BuildDeniedMetricsSet(metricsDenylist)
	if err != nil {
		log.Fatal(err)
	}
	metrics.MustRegisterMetrics(deniedMetricsSet)

	// Initialize Gin
	r := gin.Default()

	// Define /metrics route
	r.GET(cfgMetricsPath, metrics.Handler)

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "up",
		})
	})

	// Start exporting metrics and periodically fetch them
	go func() {
		for {
			// Perform metrics fetch logic
			go metrics.FetchMetrics()
			// Sleep for a certain interval before fetching metrics again
			time.Sleep(time.Minute)
		}
	}()

	// Start the Gin server
	logging.Info("Beginning to serve metrics on ", viper.GetString("listen"))
	if err := r.Run(viper.GetString("listen")); err != nil {
		log.Fatal("Error starting server: ", err)
	}
}
