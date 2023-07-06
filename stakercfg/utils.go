package stakercfg

import (
	"encoding/hex"
	"io"
	"os"
)

func ReadCertFile(rawCert string, certFilePath string) ([]byte, error) {
	if rawCert != "" {
		rpcCert, err := hex.DecodeString(rawCert)
		if err != nil {
			return nil, err
		}
		return rpcCert, nil

	} else {
		certFile, err := os.Open(certFilePath)
		if err != nil {
			return nil, err
		}
		defer certFile.Close()

		rpcCert, err := io.ReadAll(certFile)
		if err != nil {
			return nil, err
		}

		return rpcCert, nil
	}
}
