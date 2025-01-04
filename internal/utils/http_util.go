package utils

import "net/http"

func GetRequest(url string) (*http.Response, error) {
	return http.Get(url)
}
