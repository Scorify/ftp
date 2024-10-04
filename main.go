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
	Target         string `key:"target"`
	Port           int    `key:"port" default:"21"`
	Username       string `key:"username" default:"anonymous"`
	Password       string `key:"password"`
	File           string `key:"file"`
	MatchType      string `key:"matchType" default:"exists" enum:"exists,substringMatch,regexMatch,exactMatch,sha256,md5,sha1"`
	ExpectedOutput string `key:"expectedOutput"`
}

func Validate(config string) error {
	conf := Schema{}

	err := schema.Unmarshal([]byte(config), &conf)
	if err != nil {
		return fmt.Errorf("encountered error unmarshalling config: %v", err)
	}

	if conf.Target == "" {
		return fmt.Errorf("target must be provided; got: %s", conf.Target)
	}

	if conf.Port == 0 {
		return fmt.Errorf("port must be provided; got: %d", conf.Port)
	}

	if conf.Username == "" {
		return fmt.Errorf("username must be provided; got: %s", conf.Username)
	}

	if !slices.Contains([]string{"exists", "substringMatch", "regexMatch", "exactMatch", "sha256", "md5", "sha1"}, conf.MatchType) {
		return fmt.Errorf("matchType must be one of: exists, substringMatch, regexMatch, exactMatch, sha256, md5, sha1; got: %s", conf.MatchType)
	}

	if conf.ExpectedOutput == "" && conf.MatchType != "exists" {
		return fmt.Errorf("expectedOutput must be provided for all comparison types except exists; got: %s", conf.ExpectedOutput)
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
