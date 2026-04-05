package desec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Config struct {
	APITokenSecretRef cmmeta.SecretKeySelector `json:"apiTokenSecretRef"`
}

type Solver struct {
	kClient   kubernetes.Interface
	newClient func(token string) DNSClient
}

func NewSolver() *Solver {
	return &Solver{}
}

func (s *Solver) Name() string {
	return "desec"
}

func (s *Solver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}
	s.kClient = cl
	s.newClient = func(token string) DNSClient {
		return NewClient(token)
	}
	return nil
}

func extractDomainAndSubname(fqdn, zone string) (domain, subname string) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")
	domain = zone
	if fqdn == zone {
		subname = ""
	} else {
		subname = strings.TrimSuffix(fqdn, "."+zone)
	}
	return domain, subname
}

func loadConfig(cfgJSON *extapi.JSON) (Config, error) {
	cfg := Config{}
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %w", err)
	}
	return cfg, nil
}

func (s *Solver) getAPIToken(ch *v1alpha1.ChallengeRequest, cfg Config) (string, error) {
	ref := cfg.APITokenSecretRef
	secret, err := s.kClient.CoreV1().Secrets(ch.ResourceNamespace).Get(
		context.Background(), ref.Name, metav1.GetOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("fetching secret %s/%s: %w", ch.ResourceNamespace, ref.Name, err)
	}
	tokenBytes, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", ref.Key, ch.ResourceNamespace, ref.Name)
	}
	return strings.TrimSpace(string(tokenBytes)), nil
}

func (s *Solver) resolveToken(ch *v1alpha1.ChallengeRequest, cfg Config) (string, error) {
	if ch.AllowAmbientCredentials {
		if token := os.Getenv("DESEC_API_TOKEN"); token != "" {
			return token, nil
		}
	}
	return s.getAPIToken(ch, cfg)
}

func (s *Solver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	token, err := s.resolveToken(ch, cfg)
	if err != nil {
		return err
	}
	domain, subname := extractDomainAndSubname(ch.ResolvedFQDN, ch.ResolvedZone)
	client := s.newClient(token)
	return s.presentWithClient(client, domain, subname, ch.Key)
}

func (s *Solver) presentWithClient(client DNSClient, domain, subname, key string) error {
	ctx := context.Background()
	quotedKey := QuoteTXT(key)

	existing, err := client.GetRRset(ctx, domain, subname)
	if errors.Is(err, ErrNotFound) {
		return client.CreateRRset(ctx, domain, RRset{
			Subname: subname,
			Type:    "TXT",
			Records: []string{quotedKey},
			TTL:     defaultTTL,
		})
	}
	if err != nil {
		return fmt.Errorf("checking existing RRset: %w", err)
	}

	for _, r := range existing.Records {
		if r == quotedKey {
			return nil
		}
	}

	records := append(existing.Records, quotedKey)
	return client.UpdateRRset(ctx, domain, subname, records)
}

func (s *Solver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	token, err := s.resolveToken(ch, cfg)
	if err != nil {
		return err
	}
	domain, subname := extractDomainAndSubname(ch.ResolvedFQDN, ch.ResolvedZone)
	client := s.newClient(token)
	return s.cleanUpWithClient(client, domain, subname, ch.Key)
}

func (s *Solver) cleanUpWithClient(client DNSClient, domain, subname, key string) error {
	ctx := context.Background()
	quotedKey := QuoteTXT(key)

	existing, err := client.GetRRset(ctx, domain, subname)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking existing RRset: %w", err)
	}

	var remaining []string
	found := false
	for _, r := range existing.Records {
		if r == quotedKey {
			found = true
			continue
		}
		remaining = append(remaining, r)
	}

	if !found {
		return nil
	}

	if len(remaining) == 0 {
		return client.DeleteRRset(ctx, domain, subname)
	}

	return client.UpdateRRset(ctx, domain, subname, remaining)
}
