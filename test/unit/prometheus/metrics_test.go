package prometheus_test

import (
	"testing"

	cloudflareAPI "github.com/lablabs/cloudflare-exporter/internal/cloudflare"
	"github.com/lablabs/cloudflare-exporter/internal/models"

	"github.com/stretchr/testify/mock"
)

// MockGraphQLClient is a mocked version of a GraphQL client
type MockGraphQLClient struct {
	mock.Mock
}

func (m *MockGraphQLClient) Execute(query string, variables map[string]interface{}) (interface{}, error) {
	args := m.Called(query, variables)
	return args.Get(0), args.Error(1)
}

func TestFetchWorkerTotals_Error(t *testing.T) {
	// Create a mock GraphQL client
	mockClient := new(MockGraphQLClient)

	// Set up the mock data response for a successful request
	mockData := &models.CloudflareResponseAccts{
		Viewer: struct {
			Accounts []models.AccountResp `json:"accounts"`
		}{
			Accounts: []models.AccountResp{},
		},
	}

	accountID := "mockAccountID"
	resp, err := cloudflareAPI.FetchWorkerTotals(accountID)

	// Validate the results or errors
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Errorf("expected response, got nil")
	}

	// Set up the mock to return the mock data when the Execute method is called
	mockClient.On("Execute", mock.Anything, mock.Anything).Return(mockData, nil)

	// Ensure that the Execute method was called as expected
	mockClient.AssertExpectations(t)
}
