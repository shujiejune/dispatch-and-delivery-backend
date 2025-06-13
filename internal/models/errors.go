package models

import "errors"

var ErrNotFound = errors.New("requested resource not found")
var ErrForbidden = errors.New("user does not have permission to access this resource")
var ErrConflict = errors.New("resource conflict, item already exists")

// Add other common domain errors
