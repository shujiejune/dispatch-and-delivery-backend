package models

// ErrorResponse is a generic structure for JSON error responses.
type ErrorResponse struct {
	Message string `json:"message"`
	Details string `json:"details,omitempty"` // Optional additional details
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Page       int         `json:"page"`
	Limit      int         `json:"limit"`
	Total      int         `json:"total"`
	TotalPages int         `json:"total_pages"`
}

func NewPaginatedResponse(data interface{}, page, limit, total int) PaginatedResponse {
	totalPages := 0
	if limit > 0 && total > 0 {
		totalPages = (total + limit - 1) / limit
	}
	return PaginatedResponse{
		Data:       data,
		Page:       page,
		Limit:      limit,
		Total:      total,
		TotalPages: totalPages,
	}
}
