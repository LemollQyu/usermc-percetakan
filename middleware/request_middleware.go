package middleware

import (
	"bytes"
	"context"
	"io"
	"time"
	"usermc/infrastructure/log"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := uuid.New().String()

		timeoutCtx, cencel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cencel()

		ctx := context.WithValue(timeoutCtx, "request_id", requestID)
		c.Request = c.Request.WithContext(ctx)

		var payloadString string

		// Hanya memproses body untuk metode POST, PUT, atau PATCH
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			// Baca seluruh Request Body
			bodyBytes, err := io.ReadAll(c.Request.Body)

			if err != nil {
				// Jika gagal membaca, set payloadString kosong atau error
				payloadString = "Error reading request body: " + err.Error()
			} else {
				// Konversi bytes menjadi string untuk Logging
				payloadString = string(bodyBytes)
			}

			// PENTING: Rewind Request Body
			// Kembalikan stream body agar handler utama (misalnya c.BindJSON) dapat membacanya.
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		startTime := time.Now()
		c.Next()
		latency := time.Since(startTime)

		requestLog := logrus.Fields{
			"request_id": requestID,
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"status":     c.Writer.Status(),
			"latency":    latency,
			"payload":    payloadString,
		}

		if c.Writer.Status() == 200 || c.Writer.Status() == 201 {
			log.Logger.WithFields(requestLog).Info("Request success")
		} else {
			log.Logger.WithFields(requestLog).Info("Request error!")
		}

	}
}
