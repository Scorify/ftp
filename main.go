package ftp

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"regexp"

	"github.com/jlaffaye/ftp"
)

type Schema struct {
	Target         string `json:"target"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	File           string `json:"file"`
	Exists         bool   `json:"exists"`
	SubstringMatch bool   `json:"substringMatch"`
	RegexMatch     bool   `json:"regexMatch"`
	ExactMatch     bool   `json:"exactMatch"`
	SHA256         bool   `json:"sha256"`
	MD5            bool   `json:"md5"`
	SHA1           bool   `json:"sslCert"`
	ExpectedOutput string `json:"expectedOutput"`
}

func ValidateConfig(config *Schema) error {
	if config.Target == "" {
		return fmt.Errorf("target must be provided")
	}

	if config.Port == 0 {
		return fmt.Errorf("port must be provided")
	}

	comparisonType := []string{}
	if config.Exists {
		comparisonType = append(comparisonType, "exists")
	}

	if config.SubstringMatch {
		comparisonType = append(comparisonType, "substringMatch")
	}

	if config.RegexMatch {
		comparisonType = append(comparisonType, "regexMatch")
	}

	if config.ExactMatch {
		comparisonType = append(comparisonType, "exactMatch")
	}

	if config.SHA256 {
		comparisonType = append(comparisonType, "sha256")
	}

	if config.MD5 {
		comparisonType = append(comparisonType, "md5")
	}

	if config.SHA1 {
		comparisonType = append(comparisonType, "sha1")
	}

	if len(comparisonType) == 0 {
		return fmt.Errorf("exactly one comparison type must be provided; provided none")
	}

	if len(comparisonType) > 1 {
		return fmt.Errorf("exactly one comparison type must be provided; provided multiple: %v", comparisonType)
	}

	if config.ExpectedOutput == "" && !config.Exists {
		return fmt.Errorf("expectedOutput must be provided for all comparison types except exists")
	}

	return nil
}

func Run(ctx context.Context, config string) error {
	schema := Schema{}

	err := json.Unmarshal([]byte(config), &schema)
	if err != nil {
		return err
	}

	err = ValidateConfig(&schema)
	if err != nil {
		return fmt.Errorf("invalid config: %v", err)
	}

	connStr := fmt.Sprintf("%s:%d", schema.Target, schema.Port)

	conn, err := ftp.Dial(connStr, ftp.DialWithContext(ctx))
	if err != nil {
		return fmt.Errorf("encountered error creating ftp connection: %v", err)
	}
	defer conn.Quit()

	err = conn.Login(schema.Username, schema.Password)
	if err != nil {
		return fmt.Errorf("encountered error logging in: %v", err)
	}
	defer conn.Logout()

	resp, err := conn.Retr(schema.File)
	if err != nil {
		return fmt.Errorf("encountered error retrieving file: %v", err)
	}
	defer resp.Close()

	if resp == nil {
		return fmt.Errorf("response is nil")
	}

	bodyBytes, err := io.ReadAll(resp)
	if err != nil {
		return fmt.Errorf("encountered error reading response body: %v", err)
	}

	if schema.Exists {
		return nil
	}

	if schema.SubstringMatch {
		if bytes.Contains(bodyBytes, []byte(schema.ExpectedOutput)) {
			return nil
		}
		return fmt.Errorf("response does not match substring: %s", schema.ExpectedOutput)
	}

	if schema.RegexMatch {
		pattern, err := regexp.Compile(schema.ExpectedOutput)
		if err != nil {
			return fmt.Errorf("encountered error compiling regex pattern: %v", err)
		}

		if pattern.Match(bodyBytes) {
			return nil
		}
		return fmt.Errorf("response does not match regex pattern: %s", schema.ExpectedOutput)
	}

	if schema.ExactMatch {
		if string(bodyBytes) == schema.ExpectedOutput {
			return nil
		}
		return fmt.Errorf("response does not match expected output")
	}

	if schema.SHA256 {
		sha256 := fmt.Sprintf("%x", sha256.Sum256(bodyBytes))
		if sha256 == schema.ExpectedOutput {
			return nil
		}
		return fmt.Errorf("response does not match expected sha256: %s", schema.ExpectedOutput)
	}

	if schema.MD5 {
		md5 := fmt.Sprintf("%x", md5.Sum(bodyBytes))
		if md5 == schema.ExpectedOutput {
			return nil
		}
		return fmt.Errorf("response does not match expected md5: %s", schema.ExpectedOutput)
	}

	if schema.SHA1 {
		sha1 := fmt.Sprintf("%x", sha1.Sum(bodyBytes))
		if sha1 == schema.ExpectedOutput {
			return nil
		}
		return fmt.Errorf("response does not match expected sha1: %s", schema.ExpectedOutput)
	}

	return nil
}