package desec

import (
	"context"
	"encoding/json"
	"fmt"
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
