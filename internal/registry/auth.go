package registry

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Credential is a username and password for one registry.
type Credential struct {
	Username string
	Password string
}

// Credentials finds the credential for a registry host, by the host as the
// reference names it.
type Credentials interface {
	Lookup(registry string) (Credential, bool)
}

// DockerConfig is the static part of a Docker CLI config file: the "auths"
// map, keyed by registry host (Docker Hub's key is
// https://index.docker.io/v1/), each entry's "auth" the base64 of
// user:password or a username and password given apart. Credential helpers
// (credsStore, credHelpers) and identity tokens are not read; Helpers names
// the hosts a helper would have answered for, so an error can say why no
// credential was found.
type DockerConfig struct {
	Path    string
	auths   map[string]Credential
	helpers bool
	tokens  map[string]bool
}

type dockerConfigFile struct {
	Auths map[string]struct {
		Auth          string `json:"auth"`
		Username      string `json:"username"`
		Password      string `json:"password"`
		IdentityToken string `json:"identitytoken"`
	} `json:"auths"`
	CredsStore  string            `json:"credsStore"`
	CredHelpers map[string]string `json:"credHelpers"`
}

// DockerConfigPath is $DOCKER_CONFIG/config.json, or ~/.docker/config.json.
func DockerConfigPath() string {
	if d := os.Getenv("DOCKER_CONFIG"); d != "" {
		return filepath.Join(d, "config.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".docker", "config.json")
}

// LoadDockerConfig reads a Docker config file. A missing file is no
// credentials, not an error.
func LoadDockerConfig(path string) (*DockerConfig, error) {
	c := &DockerConfig{Path: path, auths: map[string]Credential{}, tokens: map[string]bool{}}
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var f dockerConfigFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s is not a Docker config file: %w", path, err)
	}
	c.helpers = f.CredsStore != "" || len(f.CredHelpers) > 0
	for key, a := range f.Auths {
		host := configHost(key)
		cred := Credential{Username: a.Username, Password: a.Password}
		if a.Auth != "" {
			raw, err := base64.StdEncoding.DecodeString(a.Auth)
			if err != nil {
				return nil, fmt.Errorf("%s: the auth entry for %s is not base64", path, key)
			}
			user, pass, ok := strings.Cut(string(raw), ":")
			if !ok || user == "" {
				return nil, fmt.Errorf("%s: the auth entry for %s is not user:password", path, key)
			}
			cred = Credential{Username: user, Password: strings.Trim(pass, "\x00")}
		}
		if a.IdentityToken != "" {
			c.tokens[host] = true
		}
		if cred.Username == "" {
			continue
		}
		// An exact key wins over a legacy URL-shaped key for the same host.
		if _, seen := c.auths[host]; !seen || key == host {
			c.auths[host] = cred
		}
	}
	return c, nil
}

// configHost reduces a config key to a host: Docker writes some keys as
// URLs (https://index.docker.io/v1/).
func configHost(key string) string {
	k := key
	if strings.Contains(k, "://") {
		if u, err := url.Parse(k); err == nil && u.Host != "" {
			k = u.Host
		}
	}
	k, _, _ = strings.Cut(k, "/")
	if k == "index.docker.io" || k == "registry-1.docker.io" {
		k = "docker.io"
	}
	return strings.ToLower(k)
}

// Lookup finds the static credential for a registry host.
func (c *DockerConfig) Lookup(registry string) (Credential, bool) {
	if c == nil {
		return Credential{}, false
	}
	cred, ok := c.auths[configHost(registry)]
	return cred, ok
}

// Why explains, for an error message, what the config holds for a host when
// it has no usable credential.
func (c *DockerConfig) Why(registry string) string {
	if c == nil || c.Path == "" {
		return "no Docker config file"
	}
	host := configHost(registry)
	switch {
	case c.tokens[host]:
		return fmt.Sprintf("%s holds an identity token for %s, which Socair does not use; give a username and password (or a registry access token as the password)", c.Path, registry)
	case c.helpers:
		return fmt.Sprintf("%s names a credential helper, which Socair does not run; it reads only static \"auths\" entries", c.Path)
	}
	return fmt.Sprintf("%s has no \"auths\" entry for %s", c.Path, registry)
}

// challenge is a parsed WWW-Authenticate header.
type challenge struct {
	scheme string // "bearer" or "basic", lowercased
	params map[string]string
}

// parseChallenge reads the first challenge of a WWW-Authenticate header:
// a scheme and comma-separated key="value" parameters (RFC 7235; the token
// specification's Bearer realm, service, and scope).
func parseChallenge(h string) (challenge, bool) {
	h = strings.TrimSpace(h)
	scheme, rest, _ := strings.Cut(h, " ")
	c := challenge{scheme: strings.ToLower(scheme), params: map[string]string{}}
	if c.scheme == "" {
		return c, false
	}
	for rest = strings.TrimSpace(rest); rest != ""; rest = strings.TrimSpace(rest) {
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			break
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		rest = strings.TrimSpace(rest[eq+1:])
		var val string
		if strings.HasPrefix(rest, `"`) {
			var b strings.Builder
			i := 1
			for ; i < len(rest); i++ {
				if rest[i] == '\\' && i+1 < len(rest) {
					i++
					b.WriteByte(rest[i])
					continue
				}
				if rest[i] == '"' {
					break
				}
				b.WriteByte(rest[i])
			}
			val, rest = b.String(), rest[min(i+1, len(rest)):]
		} else {
			end := strings.IndexByte(rest, ',')
			if end < 0 {
				end = len(rest)
			}
			val, rest = strings.TrimSpace(rest[:end]), rest[end:]
		}
		c.params[key] = val
		rest = strings.TrimPrefix(strings.TrimSpace(rest), ",")
	}
	return c, c.scheme == "bearer" || c.scheme == "basic"
}

func basicAuth(c Credential) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
}
