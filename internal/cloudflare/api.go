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

type cloudflareResponse struct {
	Viewer struct {
		Zones []models.ZoneResp `json:"zones"`
	} `json:"viewer"`
}

func FetchZones() []cloudflare.Zone {

	fmt.Println("fetch zones:::::")

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

	ctx := context.Background()
	z, err := api.ListZones(ctx)
	if err != nil {
		logging.Fatal(err)
	}

	return z
}

func FetchAccounts() []cloudflare.Account {

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

	ctx := context.Background()
	a, _, err := api.Accounts(ctx, cloudflare.AccountsListParams{PaginationOptions: cloudflare.PaginationOptions{PerPage: 100}})
	if err != nil {
		logging.Fatal(err)
	}

	return a
}

func FetchZoneTotals(zoneIDs []string) (*cloudflareResponse, error) {

	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-12 * time.Hour)

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

	var resp cloudflareResponse
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error(err)
		return nil, err
	}

	return &resp, nil
}

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

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseAccts
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error(err)
		return nil, err
	}

	return &resp, nil
}

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

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseLogpushAccount
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error(err)
		return nil, err
	}

	return &resp, nil
}

func ExtractZoneIDs(zones []cloudflare.Zone) []string {

	var IDs []string

	for _, z := range zones {
		IDs = append(IDs, z.ID)
	}

	return IDs
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func FilterExcludedZones(all []cloudflare.Zone, exclude []string) []cloudflare.Zone {
	var filtered []cloudflare.Zone

	if (len(exclude)) == 0 {
		return all
	}

	for _, z := range all {
		if contains(exclude, z.ID) {
			logging.Info("Exclude zone: ", z.ID, " ", z.Name)
		} else {
			filtered = append(filtered, z)
		}
	}

	return filtered
}

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
	for _, rulesetDesc := range listOfRulesets {
		if rulesetDesc.Phase == "http_request_firewall_managed" {
			ruleset, err := api.GetRuleset(ctx, cloudflare.ZoneIdentifier(zoneID), rulesetDesc.ID)
			if err != nil {
				logging.Fatal(err)
			}
			for _, rule := range ruleset.Rules {
				firewallRulesMap[rule.ID] = rule.Description
			}
		}
	}

	return firewallRulesMap
}

func FetchColoTotals(zoneIDs []string) (*models.CloudflareResponseColo, error) {

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

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseColo
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error(err)
		return nil, err
	}

	return &resp, nil
}

func FetchLoadBalancerTotals(zoneIDs []string) (*models.CloudflareResponseLb, error) {

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

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseLb
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error(err)
		return nil, err
	}

	return &resp, nil
}

func FetchLogpushZone(zoneIDs []string) (*models.CloudflareResponseLogpushZone, error) {

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

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseLogpushZone
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error(err)
		return nil, err
	}

	return &resp, nil
}

func FetchFirewallEventsAllowedDenied(zoneIDs []string) (*models.CloudflareResponseLogpushZone, error) {

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

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseLogpushZone
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error(err)
		return nil, err
	}

	return &resp, nil
}

func MagicTransitTunnelHealthChecksAdaptiveGroups(accountID string) (*models.CloudflareResponseMagicTransit, error) {

	now := time.Now().Add(-time.Duration(viper.GetInt("scrape_delay")) * time.Second).UTC()
	s := 60 * time.Second
	now = now.Truncate(s)
	now1mAgo := now.Add(-60 * time.Second)

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

	ctx := context.Background()
	graphqlClient := graphql.NewClient(cfGraphQLEndpoint)
	var resp models.CloudflareResponseMagicTransit
	if err := graphqlClient.Run(ctx, request, &resp); err != nil {
		logging.Error(err)
		return nil, err
	}
	return &resp, nil
}

func FetchSSLCertificateStatus(zoneID []string) (*models.SSLResponse, error) {
	// Define Cloudflare API endpoint for SSL certificates
	// url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/ssl/certificate_packs", "627de96e341366cf62d43c2063e8a9ac")

	// Set up the request with the proper headers
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones/627de96e341366cf62d43c2063e8a9ac/ssl/certificate_packs", nil)
	if err != nil {
		return nil, err
	}

	fmt.Println("reeeeq:::::::::::", req.Body)

	// Set the Authorization header using the API token
	req.Header.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	req.Header.Set("Content-Type", "application/json")

	// Make the API request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// If the response status is not OK, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch SSL certificates: %s", body)
	}

	// Unmarshal the response JSON into the struct
	var sslCertificate models.SSLResponse
	err = json.Unmarshal(body, &sslCertificate)
	if err != nil {
		return nil, err
	}

	// Return the parsed response
	return &sslCertificate, nil
}
