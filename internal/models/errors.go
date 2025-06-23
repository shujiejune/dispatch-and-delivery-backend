package models

import "errors"

var ErrNotFound = errors.New("requested resource not found")
var ErrForbidden = errors.New("user does not have permission to access this resource")
var ErrConflict = errors.New("resource conflict, item already exists")
var ErrInvalidToken = errors.New("token not found or expired")
var ErrInvalidCredentials = errors.New("invalid credentials") // email or password provided does not match database record
var ErrNicknameTaken = errors.New("nickname already taken")
var ErrInvalidForumPostCategoryID = errors.New("invalid category of forum post")

// Add other common domain errors
