package ftp

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/jlaffaye/ftp"
	"github.com/scorify/schema"
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
	conf := Schema{}

	err := schema.Unmarshal([]byte(config), &conf)
	if err != nil {
		return fmt.Errorf("encountered error unmarshalling config: %v", err)
	}

	connStr := fmt.Sprintf("%s:%d", conf.Target, conf.Port)

	conn, err := ftp.Dial(connStr, ftp.DialWithContext(ctx))
	if err != nil {
		return fmt.Errorf("encountered error creating ftp connection: %v", err)
	}
	defer conn.Quit()

	err = login(ctx, conn, conf.Username, conf.Password)
	if err != nil {
		return fmt.Errorf("encountered error logging in: %v", err)
	}
	defer conn.Logout()

	resp, err := retr(ctx, conn, conf.File)
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

	switch conf.MatchType {
	case "exists":
		return nil
	case "substringMatch":
		if bytes.Contains(bodyBytes, []byte(conf.ExpectedOutput)) {
			return nil
		}
		return fmt.Errorf("response does not match substring: %s", conf.ExpectedOutput)
	case "regexMatch":
		pattern, err := regexp.Compile(conf.ExpectedOutput)
		if err != nil {
			return fmt.Errorf("encountered error compiling regex pattern: %v", err)
		}

		if pattern.Match(bodyBytes) {
			return nil
		}
		return fmt.Errorf("response does not match regex pattern: %s", conf.ExpectedOutput)
	case "exactMatch":
		if string(bodyBytes) == conf.ExpectedOutput {
			return nil
		}
		return fmt.Errorf("response does not match expected output")
	case "sha256":
		sha256 := fmt.Sprintf("%x", sha256.Sum256(bodyBytes))
		if sha256 == conf.ExpectedOutput {
			return nil
		}
		return fmt.Errorf("response does not match expected sha256: %s", conf.ExpectedOutput)
	case "md5":
		md5 := fmt.Sprintf("%x", md5.Sum(bodyBytes))
		if md5 == conf.ExpectedOutput {
			return nil
		}
		return fmt.Errorf("response does not match expected md5: %s", conf.ExpectedOutput)
	case "sha1":
		sha1 := fmt.Sprintf("%x", sha1.Sum(bodyBytes))
		if sha1 == conf.ExpectedOutput {
			return nil
		}
		return fmt.Errorf("response does not match expected sha1: %s; got %s", conf.ExpectedOutput, sha1)
	default:
		return fmt.Errorf("unknown match type: %s", conf.MatchType)
	}
}

func login(ctx context.Context, conn *ftp.ServerConn, username string, password string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- conn.Login(username, password)
		close(errChan)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errChan:
		return err
	}
}

func retr(ctx context.Context, conn *ftp.ServerConn, file string) (*ftp.Response, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	type ret struct {
		resp *ftp.Response
		err  error
	}

	retChan := make(chan ret, 1)
	go func() {
		resp, err := conn.Retr(file)
		retChan <- ret{
			resp: resp,
			err:  err,
		}
		close(retChan)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-retChan:
		return ret.resp, ret.err
	}
}
