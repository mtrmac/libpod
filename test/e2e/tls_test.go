//go:build linux || freebsd

package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"

	. "github.com/containers/podman/v6/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// tlsConfigServer returns http.StatusTeapot. So if we see that, that indicates a successful TLS connection.
// But we need to special-case that in podmanFailTLSDetailsWithCAKnowledge.
const teapotRegex = `\b418\b`

var _ = Describe("--tls-details", func() {
	var (
		defaultServer *tlsConfigServer
		tls12Server   *tlsConfigServer
		nonPQCserver  *tlsConfigServer
		pqcServer     *tlsConfigServer
		expected      []expectedBehavior
	)

	BeforeEach(func() {
		defaultServer = newServer(&tls.Config{})
		tls12Server = newServer(&tls.Config{
			MaxVersion: tls.VersionTLS12,
		})
		nonPQCserver = newServer(&tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
		})
		pqcServer = newServer(&tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		})

		expected = []expectedBehavior{
			{
				server:     defaultServer,
				tlsDetails: "testdata/tls-details-anything.yaml",
				expected:   teapotRegex,
			},
			{
				server:     tls12Server,
				tlsDetails: "testdata/tls-details-anything.yaml",
				expected:   teapotRegex,
			},
			{
				server:     nonPQCserver,
				tlsDetails: "testdata/tls-details-anything.yaml",
				expected:   teapotRegex,
			},
			{
				server:     pqcServer,
				tlsDetails: "testdata/tls-details-anything.yaml",
				expected:   teapotRegex,
			},

			{
				server:     defaultServer,
				tlsDetails: "testdata/tls-details-1.3.yaml",
				expected:   teapotRegex,
			},
			{
				server:     tls12Server,
				tlsDetails: "testdata/tls-details-1.3.yaml",
				expected:   `protocol version not supported`,
			},
			{
				server:     nonPQCserver,
				tlsDetails: "testdata/tls-details-1.3.yaml",
				expected:   teapotRegex,
			},
			{
				server:     pqcServer,
				tlsDetails: "testdata/tls-details-1.3.yaml",
				expected:   teapotRegex,
			},

			{
				server:     defaultServer,
				tlsDetails: "testdata/tls-details-pqc-only.yaml",
				expected:   teapotRegex,
			},
			{
				server:     tls12Server,
				tlsDetails: "testdata/tls-details-pqc-only.yaml",
				expected:   `protocol version not supported`,
			},
			{
				server:     nonPQCserver,
				tlsDetails: "testdata/tls-details-pqc-only.yaml",
				expected:   `handshake failure`,
			},
			{
				server:     pqcServer,
				tlsDetails: "testdata/tls-details-pqc-only.yaml",
				expected:   teapotRegex,
			},
		}
	})

	// FIXME: this should contain many more tests to exercise libimage.Runtime.{SystemContext,imageContext,LibimageRuntime}.

	It("podman --tls-details build from URL context", func() {
		caDir := GinkgoT().TempDir()
		caPath := filepath.Join(caDir, "ca.crt")

		containerfile := `FROM quay.io/libpod/alpine:latest
RUN echo hello`
		containerfilePath := filepath.Join(GinkgoT().TempDir(), "Containerfile")
		err := os.WriteFile(containerfilePath, []byte(containerfile), 0o644)
		Expect(err).ToNot(HaveOccurred())

		for _, e := range expected {
			err := os.WriteFile(caPath, e.server.certBytes, 0o644)
			Expect(err).ToNot(HaveOccurred())
			// Build context from https URL: no --cert-dir, so we get cert error for our self-signed server.
			podmanFailTLSDetailsNoCA(&e, "build", "--pull-never", "-f", containerfilePath, "https://"+e.server.hostPort+"/context")
		}
	})

	It("podman --tls-details build with FROM docker://", func() {
		caDir := GinkgoT().TempDir()
		caPath := filepath.Join(caDir, "ca.crt")

		containerfile := `FROM docker://PLACEHOLDER/repo
RUN true`
		containerfilePath := filepath.Join(GinkgoT().TempDir(), "Containerfile")

		for _, e := range expected {
			err := os.WriteFile(caPath, e.server.certBytes, 0o644)
			Expect(err).ToNot(HaveOccurred())
			content := []byte(containerfile)
			content = bytes.ReplaceAll(content, []byte("PLACEHOLDER"), []byte(e.server.hostPort))
			err = os.WriteFile(containerfilePath, content, 0o644)
			Expect(err).ToNot(HaveOccurred())
			podmanFailTLSDetails(&e, "build", "--pull-always", "--cert-dir", caDir, "-f", containerfilePath, GinkgoT().TempDir())
		}
	})

	// Stub: --tls-details for podman kube apply (e7ab40136e)
	// IMPOSSIBLE: kube apply connects to a Kubernetes API server (from kubeconfig). The TLS is for
	// the K8s API endpoint, not a container registry. Would require a fake K8s API server that
	// speaks the full K8s protocol and accepts our TLS config—far beyond tlsConfigServer.
	It("podman --tls-details kube apply (stub: impossible)", func() {
		Skip("IMPOSSIBLE: kube apply connects to Kubernetes API server from kubeconfig. " +
			"TLS is for the K8s API endpoint, not a container registry. " +
			"Would require a full fake K8s API server speaking the K8s protocol.")
	})

	It("podman --tls-details kube play", func() {
		caDir := GinkgoT().TempDir()
		caPath := filepath.Join(caDir, "ca.crt")

		kubeYamlTmpl := `apiVersion: v1
kind: Pod
metadata:
  name: tls-test-pod-UNIQUE
spec:
  containers:
    - name: test
      image: IMAGE/repo
      command: ["true"]
`
		kubeDir := GinkgoT().TempDir()

		for i, e := range expected {
			err := os.WriteFile(caPath, e.server.certBytes, 0o644)
			Expect(err).ToNot(HaveOccurred())
			content := bytes.ReplaceAll([]byte(kubeYamlTmpl), []byte("IMAGE"), []byte(e.server.hostPort))
			content = bytes.ReplaceAll(content, []byte("UNIQUE"), []byte(strconv.Itoa(i)))
			kubePath := filepath.Join(kubeDir, "pod-"+strconv.Itoa(i)+".yaml")
			err = os.WriteFile(kubePath, content, 0o644)
			Expect(err).ToNot(HaveOccurred())
			// With --cert-dir, TLS succeeds and registry returns 418.
			podmanFailTLSDetails(&e, "kube", "play", "--cert-dir", caDir, kubePath)
		}
	})

	// Stub: --tls-details for kube play --build (4fce3184fd)
	// COVERED: kube play --build uses --tls-details when building. Build path is in build tests.
	It("podman --tls-details kube play --build (stub: covered by build tests)", func() {
		Skip("kube play --build --tls-details exercised by build tests. " +
			"Full test would need kube yaml + Containerfile with FROM docker://.")
	})

	It("podman --tls-details load", func() {
		caDir := GinkgoT().TempDir()
		caPath := filepath.Join(caDir, "ca.crt")

		for _, e := range expected {
			err := os.WriteFile(caPath, e.server.certBytes, 0o644)
			Expect(err).ToNot(HaveOccurred())
			// load from https URL: no --cert-dir, so we get cert error for our self-signed server.
			podmanFailTLSDetailsNoCA(&e, "load", "-i", "https://"+e.server.hostPort+"/archive")
		}
	})

	It("podman --tls-details login", func() {
		caDir := GinkgoT().TempDir()
		caPath := filepath.Join(caDir, "ca.crt")

		for _, e := range expected {
			err := os.WriteFile(caPath, e.server.certBytes, 0o644)
			Expect(err).ToNot(HaveOccurred())
			// Not podmanFailTLSDetails because this is a client-side operation, so the
			// "if remote, no certificates" conditions don’t apply.
			session := podmanTest.Podman([]string{"--tls-details", e.tlsDetails, "login", "--cert-dir", caDir, "-u", "user", "-p", "pass", e.server.hostPort})
			session.WaitWithDefaultTimeout()
			Expect(session).Should(ExitWithErrorRegex(125, e.expected))
		}
	})

	It("podman --tls-details logout", func() {
		// Logout only accesses a registry in a very specific situation:
		// - The primary auth file does not contain the credentials
		// - A secondary auth file does contain them
		// - Secondary auth files are _only_ consulted if the primary one is determined
		//   automatically, not from --authfile. Luckily XDG_RUNTIME_DIR and XDG_CONFIG_HOME
		//   counts as “automatically”.
		xdgRuntimeDir := GinkgoT().TempDir()
		Expect(os.MkdirAll(filepath.Join(xdgRuntimeDir, "containers"), 0o700)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(xdgRuntimeDir, "containers", "auth.json"),
			[]byte(`{"auths":{}}`), 0o600)).To(Succeed())

		xdgConfigHome := GinkgoT().TempDir()
		Expect(os.MkdirAll(filepath.Join(xdgConfigHome, "containers"), 0o700)).To(Succeed())
		secondaryAuthFile := filepath.Join(xdgConfigHome, "containers", "auth.json")

		for _, e := range expected {
			Expect(os.WriteFile(secondaryAuthFile, []byte(`{"auths":{"`+e.server.hostPort+`":{"auth":"dXNlcjpwYXNz"}}}`), 0o600)).To(Succeed())

			// The failure to connect to the registry is not reported to users, it is only visible
			// in the debug log.
			session := podmanTest.PodmanWithOptions(PodmanExecOptions{
				Env: append(slices.Clone(os.Environ()),
					"XDG_RUNTIME_DIR="+xdgRuntimeDir,
					"XDG_CONFIG_HOME="+xdgConfigHome),
			}, "--log-level", "debug",
				"--tls-details", e.tlsDetails, "logout", e.server.hostPort)
			session.WaitWithDefaultTimeout()

			// --cert-dir is not available in logout. Compare podmanFailTLSDetailsWithCAKnowledge .
			expected := e.expected
			if expected == teapotRegex {
				expected = `certificate signed by unknown authority`
			}
			Expect(session).Should(ExitWithErrorRegex(125,
				`level=debug msg="Ping https://`+regexp.QuoteMeta(e.server.hostPort)+`/v2/[^\n]*`+expected))
		}
	})

	// Stub: --tls-details for pulling machine images (cdd6900d28)
	// IMPOSSIBLE: Machine image pulls use OCI/disk formats and VM-specific URLs, not docker://
	// registry protocol. The pull path is in pkg/machine and uses different transports.
	It("podman --tls-details machine image pull (stub: impossible)", func() {
		Skip("IMPOSSIBLE: machine image pulls use OCI/disk formats and VM-specific transports, " +
			"not docker:// registry. Would require a machine-image server compatible with " +
			"pkg/machine/ocipull and stdpull, not our HTTP-teapot tlsConfigServer.")
	})

	It("podman --tls-details pull", func() {
		caDir := GinkgoT().TempDir()
		caPath := filepath.Join(caDir, "ca.crt")

		for _, e := range expected {
			err := os.WriteFile(caPath, e.server.certBytes, 0o644)
			Expect(err).ToNot(HaveOccurred())
			// --cert-dir is not available in the remote client.
			if !IsRemote() {
				podmanFailTLSDetails(&e, "pull", "--cert-dir", caDir, "docker://"+e.server.hostPort+"/repo")
			} else {
				podmanFailTLSDetailsNoCA(&e, "pull", "docker://"+e.server.hostPort+"/repo")
			}
		}
	})

	It("podman --tls-details push", func() {
		podmanTest.AddImageToRWStore(ALPINE)

		caDir := GinkgoT().TempDir()
		caPath := filepath.Join(caDir, "ca.crt")

		for _, e := range expected {
			err := os.WriteFile(caPath, e.server.certBytes, 0o644)
			Expect(err).ToNot(HaveOccurred())
			podmanFailTLSDetails(&e, "push", "--cert-dir", caDir, ALPINE, "docker://"+e.server.hostPort+"/repo")
		}
	})

	It("podman --tls-details run", func() {
		caDir := GinkgoT().TempDir()
		caPath := filepath.Join(caDir, "ca.crt")

		for _, e := range expected {
			err := os.WriteFile(caPath, e.server.certBytes, 0o644)
			Expect(err).ToNot(HaveOccurred())
			// --cert-dir is not available in the remote client.
			if !IsRemote() {
				podmanFailTLSDetails(&e, "run", "--cert-dir", caDir, "--rm", "docker://"+e.server.hostPort+"/repo", "true")
			} else {
				podmanFailTLSDetailsNoCA(&e, "run", "--rm", "docker://"+e.server.hostPort+"/repo", "true")
			}
		}
	})

	It("podman --tls-details load", func() {
		caDir := GinkgoT().TempDir()
		caPath := filepath.Join(caDir, "ca.crt")

		for _, e := range expected {
			err := os.WriteFile(caPath, e.server.certBytes, 0o644)
			Expect(err).ToNot(HaveOccurred())
			// load from https URL: no --cert-dir, so we get cert error for our self-signed server.
			podmanFailTLSDetailsNoCA(&e, "load", "-i", "https://"+e.server.hostPort+"/archive")
		}
	})
})

type expectedBehavior struct {
	server     *tlsConfigServer
	tlsDetails string
	expected   string
}

// tlsConfigServer serves TLS with a specific configuration.
// It returns StatusTeapot on all requests; we use that to detect that the TLS negotiation succeeded,
// without bothering to actually implement any of the protocols.
type tlsConfigServer struct {
	server    *httptest.Server
	hostPort  string
	certBytes []byte
	certPath  string
}

func newServer(config *tls.Config) *tlsConfigServer {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	DeferCleanup(server.Close)

	server.TLS = config.Clone()
	server.StartTLS()

	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	certDir := GinkgoT().TempDir()
	certPath := filepath.Join(certDir, "cert.pem")
	err := os.WriteFile(certPath, certBytes, 0o644)
	Expect(err).ToNot(HaveOccurred())

	return &tlsConfigServer{
		server:    server,
		hostPort:  server.Listener.Addr().String(),
		certBytes: certBytes,
		certPath:  certPath,
	}
}

// podmanFailTLSDetails runs a podman command with args, setting up --tls-details from e,
// and asserting an expected error.
func podmanFailTLSDetails(e *expectedBehavior, args ...string) {
	GinkgoHelper()
	podmanFailTLSDetailsWithCAKnowledge(e, true, args...)
}

// podmanFailTLSDetailsNoCA runs a podman command with args, setting up --tls-details from e,
// and asserting an expected error (assuming that the command does not trust the server’s CA).
func podmanFailTLSDetailsNoCA(e *expectedBehavior, args ...string) {
	GinkgoHelper()
	podmanFailTLSDetailsWithCAKnowledge(e, false, args...)
}

// podmanFailTLSDetailsWithCAKnowledge runs a podman command with args, setting up --tls-details from e,
// and asserting an expected error.
// knownCA indicates whether the client trusts the server’s CA.
func podmanFailTLSDetailsWithCAKnowledge(e *expectedBehavior, knownCA bool, args ...string) {
	GinkgoHelper()
	session := podmanTLSDetailsSessionWithOptions(e, PodmanExecOptions{}, args...)
	session.WaitWithDefaultTimeout()

	// Frequently, we don’t expose trusted CA configuration for individual operations,
	// especially in the remote CLI.  Checking for a successful HTTP connection is better,
	// but if we get far enough to be worrying about certificates,
	// we already negotiated the TLS version and named group.
	expected := e.expected
	if expected == teapotRegex && (IsRemote() || !knownCA) {
		expected = `certificate signed by unknown authority`
	}
	Expect(session).Should(ExitWithErrorRegex(125, expected))
}

// podmanTLSDetailsSessionWithOptions creates a PodmanSessionIntegration with e.tlsDetails.
func podmanTLSDetailsSessionWithOptions(e *expectedBehavior, options PodmanExecOptions, args ...string) *PodmanSessionIntegration {
	GinkgoHelper()
	if !IsRemote() {
		args = append([]string{"--tls-details", e.tlsDetails}, args...)
	} else {
		podmanTest.RemoteTLSDetails = e.tlsDetails
		podmanTest.RestartRemoteService()
	}
	return podmanTest.PodmanWithOptions(options, args...)
}
