package containers

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
)

const (
	bitcoindContainerName = "bitcoind-test"
)

var errRegex = regexp.MustCompile(`(E|e)rror`)

// Manager is a wrapper around all Docker instances, and the Docker API.
// It provides utilities to run and interact with all Docker containers used within e2e testing.
type Manager struct {
	ImageConfig
	pool      *dockertest.Pool
	resources map[string]*dockertest.Resource
}

// NewManager creates a new Manager instance and initializes
// all Docker specific utilities. Returns an error if initialization fails.
func NewManager() (docker *Manager, err error) {
	docker = &Manager{
		ImageConfig: NewImageConfig(),
		resources:   make(map[string]*dockertest.Resource),
	}
	docker.pool, err = dockertest.NewPool("")
	if err != nil {
		return nil, err
	}
	return docker, nil
}

func (m *Manager) CreateWalletCmd(t *testing.T, walletName string) (bytes.Buffer, bytes.Buffer, error) {
	cmd := []string{"createwallet", walletName}
	return m.ExecBitcoindCliCmd(t, cmd)
}

func (m *Manager) GetBlockCount(t *testing.T) (bytes.Buffer, bytes.Buffer, error) {
	cmd := []string{"getblockcount"}
	return m.ExecBitcoindCliCmd(t, cmd)
}

func (m *Manager) GenerateBlockCmd(t *testing.T, count int) (bytes.Buffer, bytes.Buffer, error) {
	cmd := []string{"-generate", fmt.Sprintf("%d", count)}
	return m.ExecBitcoindCliCmd(t, cmd)
}

func (m *Manager) ExecBitcoindCliCmd(t *testing.T, command []string) (bytes.Buffer, bytes.Buffer, error) {
	cmd := []string{"bitcoin-cli", "-chain=regtest", "-rpcuser=user", "-rpcpassword=pass"}
	cmd = append(cmd, command...)
	return m.ExecCmd(t, bitcoindContainerName, cmd)
}

// ExecCmd executes command by running it on the node container (specified by containerName)
// success is the output of the command that needs to be observed for the command to be deemed successful.
// It is found by checking if stdout or stderr contains the success string anywhere within it.
// returns container std out, container std err, and error if any.
// An error is returned if the command fails to execute or if the success string is not found in the output.
func (m *Manager) ExecCmd(t *testing.T, containerName string, command []string) (bytes.Buffer, bytes.Buffer, error) {
	if _, ok := m.resources[containerName]; !ok {
		return bytes.Buffer{}, bytes.Buffer{}, fmt.Errorf("no resource %s found", containerName)
	}
	containerId := m.resources[containerName].Container.ID

	var (
		outBuf bytes.Buffer
		errBuf bytes.Buffer
	)

	timeout := 20 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	t.Logf("\n\nRunning: \"%s\"", command)

	// We use the `require.Eventually` function because it is only allowed to do one transaction per block without
	// sequence numbers. For simplicity, we avoid keeping track of the sequence number and just use the `require.Eventually`.
	require.Eventually(
		t,
		func() bool {
			exec, err := m.pool.Client.CreateExec(docker.CreateExecOptions{
				Context:      ctx,
				AttachStdout: true,
				AttachStderr: true,
				Container:    containerId,
				Cmd:          command,
			})
			require.NoError(t, err)

			err = m.pool.Client.StartExec(exec.ID, docker.StartExecOptions{
				Context:      ctx,
				Detach:       false,
				OutputStream: &outBuf,
				ErrorStream:  &errBuf,
			})
			if err != nil {
				return false
			}

			errBufString := errBuf.String()
			// Note that this does not match all errors.
			// This only works if CLI outputs "Error" or "error"
			// to stderr.
			if errRegex.MatchString(errBufString) {
				t.Log("\nstderr:")
				t.Log(errBufString)

				t.Log("\nstdout:")
				t.Log(outBuf.String())
				// N.B: We should not be returning false here
				// because some applications such as Hermes might log
				// "error" to stderr when they function correctly,
				// causing test flakiness. This log is needed only for
				// debugging purposes.
				return false
			}

			return true
		},
		timeout,
		100*time.Millisecond,
		"command failed",
	)

	return outBuf, errBuf, nil
}

func (m *Manager) RunBitcoindResource(
	bitcoindCfgPath string,
) (*dockertest.Resource, error) {
	bitcoindResource, err := m.pool.RunWithOptions(
		&dockertest.RunOptions{
			Name:       bitcoindContainerName,
			Repository: m.BitcoindRepository,
			Tag:        m.BitcoindVersion,
			Mounts: []string{
				fmt.Sprintf("%s/:/data/.bitcoin", bitcoindCfgPath),
			},
			ExposedPorts: []string{
				"8332",
				"8333",
				"28332",
				"28333",
				"18443",
			},
			PortBindings: map[docker.Port][]docker.PortBinding{
				"8332/tcp":  {{HostIP: "", HostPort: "8332"}},
				"8333/tcp":  {{HostIP: "", HostPort: "8333"}},
				"28332/tcp": {{HostIP: "", HostPort: "28332"}},
				"28333/tcp": {{HostIP: "", HostPort: "28333"}},
				"18443/tcp": {{HostIP: "", HostPort: "18443"}},
			},
			Cmd: []string{
				"-regtest",
				"-rpcuser=user",
				"-rpcpassword=pass",
				"-rpcallowip=0.0.0.0/0",
				"-rpcbind=0.0.0.0",
			},
		},
		noRestart,
	)
	if err != nil {
		return nil, err
	}
	m.resources[bitcoindContainerName] = bitcoindResource
	return bitcoindResource, nil
}

// PurgeResource purges the container resource and returns an error if any.
func (m *Manager) PurgeResource(resource *dockertest.Resource) error {
	return m.pool.Purge(resource)
}

// GetResource returns the node resource for containerName.
func (m *Manager) GetResource(containerName string) (*dockertest.Resource, error) {
	resource, exists := m.resources[containerName]
	if !exists {
		return nil, fmt.Errorf("node resource not found: container name: %s", containerName)
	}
	return resource, nil
}

// GetHostPort returns the port-forwarding address of the running host
// necessary to connect to the portId exposed inside the container.
// The container is determined by containerName.
// Returns the host-port or error if any.
func (m *Manager) GetHostPort(containerName string, portId string) (string, error) {
	resource, err := m.GetResource(containerName)
	if err != nil {
		return "", err
	}
	return resource.GetHostPort(portId), nil
}

// RemoveResource removes a node container specified by containerName.
// Returns error if any.
func (m *Manager) RemoveResource(containerName string) error {
	resource, err := m.GetResource(containerName)
	if err != nil {
		return err
	}
	var opts docker.RemoveContainerOptions
	opts.ID = resource.Container.ID
	opts.Force = true
	if err := m.pool.Client.RemoveContainer(opts); err != nil {
		return err
	}
	delete(m.resources, containerName)
	return nil
}

// ClearResources removes all outstanding Docker resources created by the Manager.
func (m *Manager) ClearResources() error {
	for _, resource := range m.resources {
		if err := m.pool.Purge(resource); err != nil {
			return err
		}
	}

	return nil
}

func noRestart(config *docker.HostConfig) {
	// in this case we don't want the nodes to restart on failure
	config.RestartPolicy = docker.RestartPolicy{
		Name: "no",
	}
}
