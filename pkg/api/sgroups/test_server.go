package sgroups

import sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"

var (
	// NewSgroupsAPI - reexports func to create testing SGroups API server
	NewSgroupsAPI = sgAPI.NewBackendServerAPI

	_ = NewSgroupsAPI
)
