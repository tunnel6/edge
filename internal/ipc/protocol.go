package ipc

import "time"

const (
	
	Timeout = 5 * time.Second
)


type Request struct {
	Command string                 `json:"command"` // online, offline, reload, status
	Params  map[string]interface{} `json:"params"`
}


type Response struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data"`
}
