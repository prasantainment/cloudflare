package middlewares

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := c.Errors[0].Err
			log.Println("Error occurred: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Internal Server Error"})
		}
	}
}
