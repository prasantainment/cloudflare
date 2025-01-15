package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/machinebox/graphql"
	"github.com/spf13/viper"

	"github.com/lablabs/cloudflare-exporter/internal/models"
	logging "github.com/sirupsen/logrus"
)

var (
	cfGraphQLEndpoint = "https://api.cloudflare.com/client/v4/graphql/"
)

// FetchZones function returns all the zones in an arrays.
func FetchZones() []cloudflare.Zone {
	var api *cloudflare.API
	var err error
	if len(viper.GetString("cf_api_token")) > 0 {
		api, err = cloudflare.NewWithAPIToken(viper.GetString("cf_api_token"))
	} else {
		api, err = cloudflare.New(viper.GetString("cf_api_key"), viper.GetString("cf_api_email"))
	}
	if err != nil {
		logging.Fatal("Failed to initialize Cloudflare API client", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Fetch zones using the Cloudflare API
	logging.Info("Fetching zones from Cloudflare API", nil)
	ctx := context.Background()
	z, err := api.ListZones(ctx)
	if err != nil {
		logging.Fatal("Failed to fetch zones from Cloudflare API", map[string]interface{}{
			"error": err.Error(),
		})
	}

	return z
}

// FetchAccounts function return account in an array.
func FetchAccounts() []cloudflare.Account {
	var api *cloudflare.API
	var err error
	if len(viper.GetString("cf_api_token")) > 0 {
		api, err = cloudflare.NewWithAPIToken(viper.GetString("cf_api_token"))
	} else {
		api, err = cloudflare.New(viper.GetString("cf_api_key"), viper.GetString("cf_api_email"))
	}
	// Handle API client initialization error
	if err != nil {
		logging.Fatal("Failed to initialize Cloudflare API client", map[string]interface{}{
			"error": err.Error(),
		})
	}

	ctx := context.Background()
	a, _, err := api.Accounts(ctx, cloudflare.AccountsListParams{PaginationOptions: cloudflare.PaginationOptions{PerPage: 100}})
	if err != nil {
		logging.Fatal("Failed to fetch accounts from Cloudflare API", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Log the number of accounts fetched
	logging.Info("Successfully fetched accounts", map[string]interface{}{
		"account_count": len(a),
	})

	return a
}

// FetchZoneTotals retrieves aggregated metrics for the specified zone IDs, including topics like
// httpRequests1mGroups, firewallEventsAdaptiveGroups, httpRequestsAdaptiveGroups, and healthCheckEventsAdaptiveGroups.
func FetchZoneTotals(zoneIDs []string) (*models.CloudflareResponse, error) {
	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`
	query ($zoneIDs: [String!], $mintime: Time!, $maxtime: Time!, $limit: Int!)  {
		viewer {
			zones(filter: { zoneTag_in: $zoneIDs }) {
				zoneTag
				httpRequests1mGroups(limit: $limit filter: { datetime_geq: $mintime, datetime_lt: $maxtime }) {
					uniq {
						uniques
					}
					sum {
						browserMap {
							pageViews
							uaBrowserFamily
						}
						bytes
						cachedBytes
						cachedRequests
						clientHTTPVersionMap {
							clientHTTPProtocol
							requests
						}
						clientSSLMap {
							clientSSLProtocol
							requests
						}
						contentTypeMap {
							bytes
							requests
							edgeResponseContentTypeName
						}
						countryMap {
							bytes
							clientCountryName
							requests
							threats
						}
						encryptedBytes
						encryptedRequests
						ipClassMap {
							ipType
							requests
						}
						pageViews
						requests
						responseStatusMap {
							edgeResponseStatus
							requests
						}
						threatPathingMap {
							requests
							threatPathingName
						}
						threats
					}
					dimensions {
						datetime
					}
				}
				firewallEventsAdaptiveGroups(limit: $limit, filter: { datetime_geq: $mintime, datetime_lt: $maxtime }) {
					count
					dimensions {
					action
					source
					ruleId
					clientRequestHTTPHost
					clientCountryName
					}
				}
				httpRequestsAdaptiveGroups(limit: $limit, filter: { datetime_geq: $mintime, datetime_lt: $maxtime, cacheStatus_notin: ["hit"] }) {
					count
					dimensions {
						originResponseStatus
						clientCountryName
						clientRequestHTTPHost
					}
				}
				httpRequestsEdgeCountryHost: httpRequestsAdaptiveGroups(limit: $limit, filter: { datetime_geq: $mintime, datetime_lt: $maxtime }) {
					count
					dimensions {
						edgeResponseStatus
						clientCountryName
						clientRequestHTTPHost
					}
				}
				healthCheckEventsAdaptiveGroups(limit: $limit, filter: { datetime_geq: $mintime, datetime_lt: $maxtime }) {
					count
					dimensions {
						healthStatus
						originIP
						region
						fqdn
					}
				}
			}
		}
	}
	`)
	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}
	request.Var("limit", 9999)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)
	request.Var("zoneIDs", zoneIDs)

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)

	// Log the query parameters for debugging
	logging.Info("Fetching zone totals from Cloudflare API", map[string]interface{}{
		"zoneIDs":           zoneIDs,
		"limit":             9999,
		"maxtime":           now,
		"mintime":           now1mAgo,
		"cfGraphQLEndpoint": cfGraphQLEndpoint,
	})

	var resp models.CloudflareResponse
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error("Failed to fetch zone totals", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, err
	}

	// Log the successful response
	logging.Info("Successfully fetched zone totals", map[string]interface{}{
		"zone_count": len(resp.Viewer.Zones),
	})

	return &resp, nil
}

// FetchWorkerTotals function query workersInvocationsAdaptive
func FetchWorkerTotals(accountID string) (*models.CloudflareResponseAccts, error) {
	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`
		query ($accountID: String!, $mintime: Time!, $maxtime: Time!, $limit: Int!) {
			viewer {
				accounts(filter: {accountTag: $accountID} ) {
					workersInvocationsAdaptive(limit: $limit, filter: { datetime_geq: $mintime, datetime_lt: $maxtime}) {
						dimensions {
							scriptName
							status
							datetime
						}

						sum {
							requests
							errors
							duration
						}

						quantiles {
							cpuTimeP50
							cpuTimeP75
							cpuTimeP99
							cpuTimeP999
							durationP50
							durationP75
							durationP99
							durationP999
						}
					}
				}
			}
		}
	`)
	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}
	request.Var("limit", 9999)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)
	request.Var("accountID", accountID)

	// Log the query parameters for debugging
	logging.Info("Fetching worker totals for Cloudflare account", map[string]interface{}{
		"accountID":         accountID,
		"limit":             9999,
		"maxtime":           now,
		"mintime":           now1mAgo,
		"cfGraphQLEndpoint": cfGraphQLEndpoint,
	})

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseAccts
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error("Failed to fetch worker totals", map[string]interface{}{
			"accountID": accountID,
			"error":     err.Error(),
		})
		return nil, err
	}

	// Log the successful response
	logging.Info("Successfully fetched worker totals", map[string]interface{}{
		"worker_count": len(resp.Viewer.Accounts),
		"accountID":    accountID,
	})

	return &resp, nil
}

// FetchLogpushAccount queries logpushHealthAdaptiveGroups and returns CloudflareResponseLogpushAccount.
func FetchLogpushAccount(accountID string) (*models.CloudflareResponseLogpushAccount, error) {
	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`query($accountID: String!, $limit: Int!, $mintime: Time!, $maxtime: Time!) {
			viewer {
			accounts(filter: {accountTag : $accountID }) {
				logpushHealthAdaptiveGroups(
				filter: {
					datetime_geq: $mintime
					datetime_lt: $maxtime
					status_neq: 200
				}
				limit: $limit
				) {
				count
				dimensions {
					jobId
					status
					destinationType
					datetime
					final
				}
				}
			}
			}
		}`)

	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}

	request.Var("accountID", accountID)
	request.Var("limit", 9999)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)

	// Log the query parameters for debugging
	logging.Info("Fetching logpush health data for Cloudflare account", map[string]interface{}{
		"accountID":         accountID,
		"limit":             9999,
		"maxtime":           now,
		"mintime":           now1mAgo,
		"cfGraphQLEndpoint": cfGraphQLEndpoint,
	})

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseLogpushAccount
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error("Failed to fetch logpush health data", map[string]interface{}{
			"accountID": accountID,
			"error":     err.Error(),
		})
		return nil, err
	}

	// Log the successful response
	logging.Info("Successfully fetched logpush health data", map[string]interface{}{
		"logpush_count": len(resp.Viewer.Accounts[0].LogpushHealthAdaptiveGroups),
		"accountID":     accountID,
	})

	return &resp, nil
}

// ExtractZoneIDs extracts zone Ids from zones and return array of zone ids.
func ExtractZoneIDs(zones []cloudflare.Zone) []string {
	var IDs []string
	for _, z := range zones {
		IDs = append(IDs, z.ID)
	}
	return IDs
}

// contains helper function
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// FilterExcludedZones excludes zones and return array of non excludes zones
func FilterExcludedZones(all []cloudflare.Zone, exclude []string) []cloudflare.Zone {
	var filtered []cloudflare.Zone

	if (len(exclude)) == 0 {
		logging.Info("No zones to exclude. Returning all zones.", nil)
		return all
	}

	for _, z := range all {
		if contains(exclude, z.ID) {
			// Log zones that are excluded
			logging.Info("Excluding zone", map[string]interface{}{
				"zoneID":   z.ID,
				"zoneName": z.Name,
			})
		} else {
			filtered = append(filtered, z)
		}
	}

	// Log the number of zones returned after filtering
	logging.Info("Filtered zones count", map[string]interface{}{
		"totalExcluded": len(all) - len(filtered),
		"totalReturned": len(filtered),
	})

	return filtered
}

// FetchFirewallRules queries firewall rules.
func FetchFirewallRules(zoneID string) map[string]string {

	var api *cloudflare.API
	var err error
	if len(viper.GetString("cf_api_token")) > 0 {
		api, err = cloudflare.NewWithAPIToken(viper.GetString("cf_api_token"))
	} else {
		api, err = cloudflare.New(viper.GetString("cf_api_key"), viper.GetString("cf_api_email"))
	}
	if err != nil {
		logging.Fatal(err)
	}

	// Log the start of the firewall rules fetch
	logging.Info("Fetching firewall rules for zone", map[string]interface{}{
		"zoneID": zoneID,
	})

	ctx := context.Background()
	listOfRules, _, err := api.FirewallRules(ctx,
		cloudflare.ZoneIdentifier(zoneID),
		cloudflare.FirewallRuleListParams{})
	if err != nil {
		logging.Fatal(err)
	}
	firewallRulesMap := make(map[string]string)

	for _, rule := range listOfRules {
		firewallRulesMap[rule.ID] = rule.Description
	}

	listOfRulesets, err := api.ListRulesets(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.ListRulesetsParams{})
	if err != nil {
		logging.Fatal(err)
	}

	logging.Info("Fetched rulesets", map[string]interface{}{
		"zoneID":          zoneID,
		"rulesetsFetched": len(listOfRulesets),
	})

	for _, rulesetDesc := range listOfRulesets {
		if rulesetDesc.Phase == "http_request_firewall_managed" {
			ruleset, err := api.GetRuleset(ctx, cloudflare.ZoneIdentifier(zoneID), rulesetDesc.ID)
			if err != nil {
				logging.Info("Fetched managed ruleset", map[string]interface{}{
					"zoneID":       zoneID,
					"rulesetID":    rulesetDesc.ID,
					"rulesetName":  rulesetDesc.Name,
					"rulesFetched": len(ruleset.Rules),
				})
			}
			for _, rule := range ruleset.Rules {
				firewallRulesMap[rule.ID] = rule.Description
			}
		}
	}

	// Log the number of rules collected
	logging.Info("Total firewall rules collected", map[string]interface{}{
		"zoneID":     zoneID,
		"totalRules": len(firewallRulesMap),
	})

	return firewallRulesMap
}

// FetchColoTotals returns queries httpRequestsAdaptiveGroups.
func FetchColoTotals(zoneIDs []string) (*models.CloudflareResponseColo, error) {

	// Log the start of the process
	logging.Info("Fetching Colo totals for zoneIDs", map[string]interface{}{
		"zoneIDs": zoneIDs,
	})

	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`
	query ($zoneIDs: [String!], $mintime: Time!, $maxtime: Time!, $limit: Int!) {
		viewer {
			zones(filter: { zoneTag_in: $zoneIDs }) {
				zoneTag
				httpRequestsAdaptiveGroups(
					limit: $limit
					filter: { datetime_geq: $mintime, datetime_lt: $maxtime }
					) {
						count
						avg {
							sampleInterval
						}
						dimensions {
							clientRequestHTTPHost
							coloCode
							datetime
						}
						sum {
							edgeResponseBytes
							visits
						}
					}
				}
			}
		}
`)
	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}
	request.Var("limit", 9999)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)
	request.Var("zoneIDs", zoneIDs)

	// Log request variables
	logging.Info("GraphQL request variables", map[string]interface{}{
		"limit":   9999,
		"maxtime": now,
		"mintime": now1mAgo,
		"zoneIDs": zoneIDs,
	})

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseColo
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		// Log the error if request fails
		logging.Error("Failed to fetch Colo totals", map[string]interface{}{
			"error": err,
		})
		return nil, err
	}

	// Log success after receiving response
	logging.Info("Successfully fetched Colo totals", map[string]interface{}{
		"zoneIDs":  zoneIDs,
		"response": resp,
	})

	return &resp, nil
}

// FetchLoadBalancerTotals returns data by querying loadBalancingRequestsAdaptiveGroups and loadBalancingRequestsAdaptive.
func FetchLoadBalancerTotals(zoneIDs []string) (*models.CloudflareResponseLb, error) {
	// Log the start of the process
	logging.Info("Fetching Load Balancer totals for zoneIDs", map[string]interface{}{
		"zoneIDs": zoneIDs,
	})

	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`
	query ($zoneIDs: [String!], $mintime: Time!, $maxtime: Time!, $limit: Int!) {
		viewer {
			zones(filter: { zoneTag_in: $zoneIDs }) {
				zoneTag
				loadBalancingRequestsAdaptiveGroups(
					filter: { datetime_geq: $mintime, datetime_lt: $maxtime},
					limit: $limit) {
					count
					dimensions {
						region
						lbName
						selectedPoolName
						proxied
						selectedOriginName
						selectedPoolAvgRttMs
						selectedPoolHealthy
						steeringPolicy
					}
				}
				loadBalancingRequestsAdaptive(
					filter: { datetime_geq: $mintime, datetime_lt: $maxtime},
					limit: $limit) {
					lbName
					proxied
					region
					selectedPoolHealthy
					selectedPoolId
					selectedPoolName
					sessionAffinityStatus
					steeringPolicy
					selectedPoolAvgRttMs
					pools {
						id
						poolName
						healthy
						avgRttMs
					}
					origins {
						originName
						health
						ipv4
						selected
					}
				}
			}
		}
	}
`)
	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}
	request.Var("limit", 9999)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)
	request.Var("zoneIDs", zoneIDs)

	// Log request variables
	logging.Info("GraphQL request variables", map[string]interface{}{
		"limit":   9999,
		"maxtime": now,
		"mintime": now1mAgo,
		"zoneIDs": zoneIDs,
	})

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseLb
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		// Log the error if request fails
		logging.Error("Failed to fetch Load Balancer totals", map[string]interface{}{
			"error": err,
		})
		return nil, err
	}

	// Log success after receiving response
	logging.Info("Successfully fetched Load Balancer totals", map[string]interface{}{
		"zoneIDs":  zoneIDs,
		"response": resp,
	})

	return &resp, nil
}

// FetchLogpushZone query logpushHealthAdaptiveGroups and return CloudflareResponseLogpushZone
func FetchLogpushZone(zoneIDs []string) (*models.CloudflareResponseLogpushZone, error) {
	// Log the start of the process
	logging.Info("Fetching Logpush zone for zoneIDs", map[string]interface{}{
		"zoneIDs": zoneIDs,
	})

	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`query($zoneIDs: String!, $limit: Int!, $mintime: Time!, $maxtime: Time!) {
		viewer {
			zones(filter: {zoneTag_in : $zoneIDs }) {
			logpushHealthAdaptiveGroups(
			  filter: {
				datetime_geq: $mintime
				datetime_lt: $maxtime
				status_neq: 200
			  }
			  limit: $limit
			) {
			  count
			  dimensions {
				jobId
				status
				destinationType
				datetime
				final
			  }
			}
		  }
		}
	  }`)

	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}

	request.Var("zoneIDs", zoneIDs)
	request.Var("limit", 9999)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)

	// Log request variables
	logging.Info("GraphQL request variables", map[string]interface{}{
		"zoneIDs": zoneIDs,
		"limit":   9999,
		"maxtime": now,
		"mintime": now1mAgo,
	})

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseLogpushZone
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error(err)
		return nil, err
	}

	// Log success after receiving response
	logging.Info("Successfully fetched Logpush zone data", map[string]interface{}{
		"zoneIDs":  zoneIDs,
		"response": resp,
	})

	return &resp, nil
}

// FetchFirewallEventsAllowedDenied queries logpushHealthAdaptiveGroups.
func FetchFirewallEventsAllowedDenied(zoneIDs []string) (*models.CloudflareResponseLogpushZone, error) {
	// Log the start of the process
	logging.Info("Fetching firewall events for allowed/denied status", map[string]interface{}{
		"zoneIDs": zoneIDs,
	})

	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	request := graphql.NewRequest(`query($zoneIDs: String!, $limit: Int!, $mintime: Time!, $maxtime: Time!) {
		viewer {
			zones(filter: {zoneTag_in : $zoneIDs }) {
			logpushHealthAdaptiveGroups(
			  filter: {
				datetime_geq: $mintime
				datetime_lt: $maxtime
				status_neq: 200
			  }
			  limit: $limit
			) {
			  count
			  dimensions {
				jobId
				status
				destinationType
				datetime
				final
			  }
			}
		  }
		}
	  }`)

	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}

	request.Var("zoneIDs", zoneIDs)
	request.Var("limit", 9999)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)

	// Log request variables
	logging.Info("GraphQL request variables", map[string]interface{}{
		"zoneIDs": zoneIDs,
		"limit":   9999,
		"maxtime": now,
		"mintime": now1mAgo,
	})

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseLogpushZone
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		// Log the error if request fails
		logging.Error("Failed to fetch firewall events", map[string]interface{}{
			"error": err,
		})
		return nil, err
	}

	// Log success after receiving response
	logging.Info("Successfully fetched firewall events for allowed/denied status", map[string]interface{}{
		"zoneIDs":  zoneIDs,
		"response": resp,
	})

	return &resp, nil
}

// MagicTransitTunnelHealthChecksAdaptiveGroups query magicTransitTunnelHealthChecksAdaptiveGroups.
func MagicTransitTunnelHealthChecksAdaptiveGroups(accountID string) (*models.CloudflareResponseMagicTransit, error) {
	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

	// Log the computed time range
	logging.Info("Computed time range for Magic Transit query", map[string]interface{}{
		"now":         now,
		"now1mAgo":    now1mAgo,
		"scrapeDelay": viper.GetInt("scrape_delay"),
	})

	request := graphql.NewRequest(`query($accountID: String!, $limit: Int!, $mintime: Time!, $maxtime: Time!) {
		viewer {
			accounts(filter: {accountTag : $accountID }) {
				magicTransitTunnelHealthChecksAdaptiveGroups(
					limit: $limit
					filter: { datetime_geq: $mintime, datetime_lt: $maxtime }
				) {
					count
					dimensions {
						active
						datetime
						edgeColoCity
						edgeColoCountry
						edgePopName
						remoteTunnelIPv4
						resultStatus
						siteName
						tunnelName
					}
				}
			}
		}
	}`)

	if len(viper.GetString("cf_api_token")) > 0 {
		request.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else {
		request.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		request.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	}

	request.Var("accountID", accountID)
	request.Var("limit", 9999)
	request.Var("maxtime", now)
	request.Var("mintime", now1mAgo)

	// Log the request headers and variables before sending the request
	logging.Info("GraphQL request details", map[string]interface{}{
		"accountID": accountID,
		"limit":     9999,
		"maxtime":   now,
		"mintime":   now1mAgo,
	})

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseMagicTransit
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error("Failed to execute GraphQL query", map[string]interface{}{
			"error":     err.Error(),
			"accountID": accountID,
			"endpoint":  cfGraphQLEndpoint,
		})
		return nil, err
	}

	// Log successful response
	logging.Info("Successfully fetched Magic Transit data", map[string]interface{}{
		"accountID": accountID,
		"count":     len(resp.Viewer.Accounts),
	})

	return &resp, nil
}

// FetchSSLCertificateStatus query cloudflare to check SSL certificate details.
func FetchSSLCertificateStatus(zoneID []string) (*models.SSLResponse, error) {
	// Define the HTTP client with a timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Prepare a combined response
	var combinedResponse models.SSLResponse

	// Iterate over the zoneIDs
	for _, zoneID := range zoneID {

		// Construct the URL dynamically for each zoneID
		url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/ssl/certificate_packs", zoneID)

		// Log API request
		logging.Info("Fetching SSL certificate status", map[string]interface{}{
			"zone_id":  zoneID,
			"endpoint": url,
		})

		// Create a new HTTP request
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			logging.Error("Failed to create request", map[string]interface{}{
				"zone_id": zoneID,
				"error":   err.Error(),
			})
			continue
		}

		if len(viper.GetString("cf_api_token")) > 0 {
			req.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
		} else {
			req.Header.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
			req.Header.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
		}
		req.Header.Set("Content-Type", "application/json")

		// Make the API request
		resp, err := client.Do(req)
		if err != nil {
			logging.Error("API request failed", map[string]interface{}{
				"zone_id": zoneID,
				"error":   err.Error(),
			})
			continue
		}
		defer resp.Body.Close()

		// Read the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response for zone %s: %w", zoneID, err)
		}

		// If the response status is not OK, return an error
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to fetch SSL data for zone %s: %s", zoneID, body)
		}

		// Unmarshal the response JSON into a temporary struct
		var tempResponse models.SSLResponse
		err = json.Unmarshal(body, &tempResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSL data for zone %s: %w", zoneID, err)
		}

		// Inject the ZoneID into each Zone object in the response
		for i := range tempResponse.Result {
			tempResponse.Result[i].ZoneID = zoneID
		}

		// Append the results to the combined response
		combinedResponse.Result = append(combinedResponse.Result, tempResponse.Result...)

		// Log response status
		logging.Info("API response received", map[string]interface{}{
			"zone_id":       zoneID,
			"status_code":   resp.StatusCode,
			"response_time": resp.Header.Get("Date"),
		})

	}
	// Return the combined response
	return &combinedResponse, nil
}
