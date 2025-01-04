package metrics

// import (
// 	"fmt"
// 	"strings"
// 	"sync"
// 	"testing"

// 	"github.com/cloudflare/cloudflare-go"
// 	"github.com/prometheus/client_golang/prometheus/testutil"
// 	"github.com/stretchr/testify/mock"
// )

// // Mock for Cloudflare API
// type MockCloudflareAPI struct {
// 	mock.Mock
// }

// func (m *MockCloudflareAPI) FetchWorkerTotals(accountID string) (*WorkerTotalsResponse, error) {
// 	args := m.Called(accountID)
// 	return args.Get(0).(*WorkerTotalsResponse), args.Error(1)
// }

// // Test fetchWorkerAnalytics
// func TestFetchWorkerAnalytics(t *testing.T) {
// 	// Mock Cloudflare API
// 	mockAPI := &MockCloudflareAPI{}
// 	cloudflareAPI = mockAPI // Replace real API with mock

// 	// Test cases
// 	tests := []struct {
// 		name            string
// 		account         cloudflare.Account
// 		apiResponse     *WorkerTotalsResponse
// 		apiError        error
// 		expectedMetrics map[string]string
// 	}{
// 		{
// 			name:    "Successful API call with data",
// 			account: cloudflare.Account{Name: "Test Account", ID: "12345"},
// 			apiResponse: &WorkerTotalsResponse{
// 				Viewer: Viewer{
// 					Accounts: []Account{
// 						{
// 							WorkersInvocationsAdaptive: []WorkerInvocation{
// 								{
// 									Dimensions: Dimensions{
// 										ScriptName: "worker1",
// 									},
// 									Sum: Summaries{
// 										Requests: 100,
// 										Errors:   5,
// 									},
// 									Quantiles: Quantile{
// 										CPUTimeP50:  0.05,
// 										DurationP50: 0.1,
// 									},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 			apiError: nil,
// 			expectedMetrics: map[string]string{
// 				`worker_requests{script_name="worker1",account="test-account"}`: "100",
// 				`worker_errors{script_name="worker1",account="test-account"}`:   "5",
// 			},
// 		},
// 		{
// 			name:        "API error with default metrics",
// 			account:     cloudflare.Account{Name: "Error Account", ID: "12345"},
// 			apiResponse: nil,
// 			apiError:    fmt.Errorf("API failed"),
// 			expectedMetrics: map[string]string{
// 				`worker_requests{script_name="unknown",account="error-account"}`: "0",
// 			},
// 		},
// 	}

// 	for _, tc := range tests {
// 		t.Run(tc.name, func(t *testing.T) {
// 			// Mock API behavior
// 			mockAPI.On("FetchWorkerTotals", tc.account.ID).Return(tc.apiResponse, tc.apiError)

// 			// Reset metrics
// 			workerRequests.Reset()
// 			workerErrors.Reset()
// 			workerCPUTime.Reset()
// 			workerDuration.Reset()

// 			// Call the function
// 			wg := &sync.WaitGroup{}
// 			fetchWorkerAnalytics(tc.account, wg)
// 			wg.Wait()

// 			// Validate metrics
// 			for metric, expectedValue := range tc.expectedMetrics {
// 				if err := testutil.CollectAndCompare(workerRequests, strings.NewReader(metric)); err != nil {
// 					t.Errorf("Metric validation failed for %s: %v", metric, err)
// 				}
// 			}

// 			// Assert mock expectations
// 			mockAPI.AssertExpectations(t)
// 		})
// 	}
// }
