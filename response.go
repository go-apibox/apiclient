package apiclient

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/go-apibox/api"
	"github.com/bitly/go-simplejson"
)

type Response struct {
	*http.Response
	bodyData []byte
}

// String return response as raw string.
func (resp *Response) String() (string, error) {
	if resp.bodyData == nil {
		var err error
		resp.bodyData, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
	}

	return string(resp.bodyData), nil
}

// Json return response as simplejson.
func (resp *Response) Json() (*simplejson.Json, error) {
	if resp.bodyData == nil {
		var err error
		resp.bodyData, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
	}

	j, err := simplejson.NewJson(resp.bodyData)
	if err != nil {
		return nil, err
	}
	return j, nil
}

// Result return response as api.Result.
func (resp *Response) Result() (*api.Result, error) {
	if resp.bodyData == nil {
		var err error
		resp.bodyData, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
	}

	var v api.Result
	dec := json.NewDecoder(strings.NewReader(string(resp.bodyData)))
	dec.UseNumber()
	err := dec.Decode(&v)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// ParseData return the DATA of the result.
// If return code is not "ok", error return.
func (resp *Response) ParseData(dataKey string, data interface{}) error {
	if resp.bodyData == nil {
		var err error
		resp.bodyData, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
	}

	dec := json.NewDecoder(strings.NewReader(string(resp.bodyData)))
	dec.UseNumber()
	for {
		t, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if v, ok := t.(string); ok {
			switch v {
			// case "ACTION":
			// case "MESSAGE":
			case "CODE":
				t, err := dec.Token()
				if err != nil {
					return err
				}
				if code, ok := t.(string); ok {
					if code != "ok" {
						// 直接返回API错误
						var v api.Result
						dec := json.NewDecoder(strings.NewReader(string(resp.bodyData)))
						dec.UseNumber()
						err := dec.Decode(&v)
						if err != nil {
							return err
						}
						return api.NewError(v.CODE, v.MESSAGE)
					}
				}
			case "DATA":
				if dataKey == "" {
					if err := dec.Decode(data); err != nil {
						return err
					}
					return nil
				} else {
					// 查找分隔符
					t, err := dec.Token()
					if err != nil {
						return err
					}
					if _, ok := t.(json.Delim); !ok {
						return errors.New("data key not found: " + dataKey)
					}

					// 查找key
					for {
						t, err = dec.Token()
						if err != nil {
							return err
						}
						if v, ok := t.(string); ok && v == dataKey {
							// 取值
							if err := dec.Decode(data); err != nil {
								return err
							}
							return nil
						}
					}

					return errors.New("data key not found: " + dataKey)
				}
			}
		}
	}

	return errors.New("data key not found: " + dataKey)
}

// RequestId return request id in response header.
func (resp *Response) RequestId() string {
	return resp.Header.Get("X-Request-Id")
}
