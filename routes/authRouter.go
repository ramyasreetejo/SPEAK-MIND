package routes

import (
	"net/http"

	controller "github.com/ramyasreetejo/speak-mind/controllers"
)

func AuthRoutes(incomingRoutes *http.ServeMux) {
	incomingRoutes.HandleFunc("/users/signup", controller.Signup) //post
	incomingRoutes.HandleFunc("/users/login", controller.Login)   //post
}
