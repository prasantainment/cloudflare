package client

import (
	"context"
	"fmt"

	"github.com/machinebox/graphql"
)

type GraphQLClient struct {
	client *graphql.Client
}

func NewGraphQLClient(endpoint string) *GraphQLClient {
	client := graphql.NewClient(endpoint)
	return &GraphQLClient{client: client}
}

func (g *GraphQLClient) Query(query string, response interface{}) error {
	req := graphql.NewRequest(query)
	err := g.client.Run(context.Background(), req, response)
	if err != nil {
		return fmt.Errorf("failed to execute query: %v", err)
	}
	return nil
}
