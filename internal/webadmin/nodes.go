package webadmin

import (
	"encoding/json"
	"net/http"
)

type localNodesResponse struct {
	Nodes []string `json:"nodes"`
}

func handleLocalNodes(
	writer http.ResponseWriter,
	request *http.Request,
	nodes nodeFinder,
) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", "GET")
		http.Error(
			writer,
			"Method not allowed.",
			http.StatusMethodNotAllowed,
		)
		return
	}

	if nodes == nil {
		localNodesUnavailable(writer)
		return
	}

	result, err := nodes.LocalNodes(request.Context())
	if err != nil {
		localNodesUnavailable(writer)
		return
	}

	if result == nil {
		result = []string{}
	}

	writer.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)
	writer.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(writer).Encode(
		localNodesResponse{
			Nodes: result,
		},
	)
}

func localNodesUnavailable(writer http.ResponseWriter) {
	http.Error(
		writer,
		"Local AREDN node discovery unavailable.",
		http.StatusServiceUnavailable,
	)
}
