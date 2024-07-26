package routes

import (
	"github.com/aungmyatmoe11/GO-JWT-Gin-MongoDB/controllers"
	"github.com/gin-gonic/gin"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("users/signup", controllers.Signup())
	incomingRoutes.POST("users/login", controllers.Login())
	// incomingRoutes.POST("/register", register)
	// incomingRoutes.POST("/logout", logout)
	// incomingRoutes.POST("/refresh-token", refreshToken)
}
