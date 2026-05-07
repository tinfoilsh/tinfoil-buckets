package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	usageclient "github.com/tinfoilsh/usage-reporting-go/client"
	"github.com/tinfoilsh/usage-reporting-go/contract"
)

const serviceName = "buckets"

type Reporter struct {
	client *usageclient.ReporterClient
}

// NewReporter returns a usage reporter that batches and signs operation events
// to the controlplane. If controlPlaneURL or secret is empty the reporter is a
// silent no-op so local development without controlplane wiring keeps working.
func NewReporter(controlPlaneURL, reporterID, secret string) (*Reporter, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(controlPlaneURL), "/")
	if endpoint == "" || secret == "" {
		return &Reporter{client: usageclient.New(usageclient.Config{})}, nil
	}
	endpoint += "/api/internal/usage-reports"
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	return &Reporter{
		client: usageclient.New(usageclient.Config{
			Endpoint: endpoint,
			Reporter: contract.Reporter{
				ID:      reporterID,
				Service: serviceName,
			},
			Secret: secret,
		}),
	}, nil
}

func validateEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid usage reporter endpoint %q: %w", endpoint, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("usage reporter endpoint %q must use https scheme", endpoint)
	}
	if parsed.Host == "" {
		return fmt.Errorf("usage reporter endpoint %q is missing a host", endpoint)
	}
	return nil
}

// ReportOperation emits a single usage event for the given operation. Each
// event carries one `requests` meter so the controlplane can charge a flat
// per-operation price configured in meter_pricing.json. The bearer API key
// is used for owner attribution; the resolved identity is attached as
// attributes for observability.
func (r *Reporter) ReportOperation(req *http.Request, id Identity, operationName string, attributes map[string]string) {
	if r == nil || r.client == nil || !r.client.Enabled() {
		return
	}
	apiKey, err := bearerToken(req.Header.Get("Authorization"))
	if err != nil || apiKey == "" {
		return
	}

	attrs := map[string]string{
		"user_id": id.UserID,
	}
	if id.OrgID != "" {
		attrs["org_id"] = id.OrgID
	}
	for k, v := range attributes {
		attrs[k] = v
	}

	r.client.AddEvent(contract.Event{
		OccurredAt: time.Now().UTC(),
		APIKey:     apiKey,
		Operation: contract.Operation{
			Service: serviceName,
			Name:    operationName,
		},
		Meters: []contract.Meter{
			{Name: "requests", Quantity: 1},
		},
		Attributes: attrs,
	})
}

func (r *Reporter) Close(ctx context.Context) error {
	if r == nil || r.client == nil {
		return nil
	}
	return r.client.Stop(ctx)
}
