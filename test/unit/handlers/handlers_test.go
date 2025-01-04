package handlers_test

// import (
// 	"net/http"
// 	"net/http/httptest"
// 	"testing"

// 	"github.com/lablabs/cloudflare-exporter/internal/handlers"
// 	"github.com/stretchr/testify/assert"
// )

// func TestHealthHandler(t *testing.T) {
// 	// Create a new HTTP request
// 	req, err := http.NewRequest(http.MethodGet, "/health", nil)
// 	assert.NoError(t, err)

// 	// Create a ResponseRecorder to capture the response
// 	rr := httptest.NewRecorder()

// 	// Create the handler
// 	handler := http.HandlerFunc(handlers.HealthCheckHandler)

// 	// Call the handler with our recorder and request
// 	handler.ServeHTTP(rr, req)

// 	// Check the response
// 	assert.Equal(t, http.StatusOK, rr.Code, "Expected status OK")
// 	assert.Equal(t, "OK", rr.Body.String(), "Expected response body to be OK")
// }

// func TestHealthCheckHandler(t *testing.T) {
// 	r := gin.Default()
// 	r.GET("/health", metrics.Handler)

// 	req := httptest.NewRequest("GET", "/health", nil)
// 	w := httptest.NewRecorder()

// 	r.ServeHTTP(w, req)

// 	if w.Code != 200 {
// 		t.Fatalf("Expected status 200, got %d", w.Code)
// 	}
// }
