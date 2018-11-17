package apiclient

import (
	"net/http"
	"net/url"

	"github.com/go-apibox/api"
)

func (client *Client) GetData(action string, params url.Values, header http.Header, dataKey string, data interface{}) error {
	resp, err := client.Get(action, params, header)
	if err != nil {
		return err
	}
	if err := resp.ParseData(dataKey, data); err != nil {
		return err
	}
	return nil
}

func (client *Client) PostData(action string, params url.Values, header http.Header, dataKey string, data interface{}) error {
	resp, err := client.Post(action, params, header)
	if err != nil {
		return err
	}
	if err := resp.ParseData(dataKey, data); err != nil {
		return err
	}
	return nil
}

func (client *Client) GetResult(action string, params url.Values, header http.Header) (*api.Result, error) {
	resp, err := client.Get(action, params, header)
	if err != nil {
		return nil, err
	}
	result, err := resp.Result()
	if err != nil {
		return nil, err
	}
	if result.CODE != "ok" {
		return nil, api.NewError(result.CODE, result.MESSAGE)
	}
	return result, nil
}

func (client *Client) PostResult(action string, params url.Values, header http.Header) (*api.Result, error) {
	resp, err := client.Post(action, params, header)
	if err != nil {
		return nil, err
	}
	result, err := resp.Result()
	if err != nil {
		return nil, err
	}
	if result.CODE != "ok" {
		return nil, api.NewError(result.CODE, result.MESSAGE)
	}
	return result, nil
}
