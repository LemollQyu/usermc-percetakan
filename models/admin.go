package models

type RequestLoginAdmin struct {
	Username string `json:"username" binding:"required,max=100,min=3"`
	Password string `json:"password" binding:"required,max=100,min=3"`
}
