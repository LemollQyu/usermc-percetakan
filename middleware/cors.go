package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CORS returns a middleware that sets CORS headers so frontend (e.g. localhost:3000) can call this API.
func CORS(allowOrigins []string) gin.HandlerFunc {
	origins := allowOrigins
	if len(origins) == 0 {
		origins = []string{"http://localhost:3000"}
	}
	originSet := make(map[string]bool)
	for _, o := range origins {
		originSet[o] = true
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if originSet[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
		} else if originSet["*"] {
			c.Header("Access-Control-Allow-Origin", "*")
		} else if origin != "" {
			// Allow any localhost port for development
			c.Header("Access-Control-Allow-Origin", origin)
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
