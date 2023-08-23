package main

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Image struct {
	ID       int    `json:"id"`
	UserID   int    `json:"user_id"`
	ImageURL string `json:"image_url"`
}

type ImageRequestBody struct {
	Base64Image string `json:"base64Image"`
}

var secretKey = []byte("joweighreuhernvorwinvreoi")

func main() {
	r := gin.Default()

	r.POST("/login", loginHandler)

	r.Use(authMiddleware)

	r.POST("/upload-picture", uploadPictureHandler)
	r.GET("/images", getImagesHandler)

	r.Run(":8080")

}

func authMiddleware(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		c.Abort()
		return
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(tokenString, prefix) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		c.Abort()
		return
	}

	tokenString = tokenString[len(prefix):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	c.Next()
}

func loginHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	database, err := sql.Open("sqlite3", "db/mydb.db")
	if err != nil {
		log.Fatal(err)
	}

	rows, nil := database.Query("SELECT id, username, password_hash FROM users WHERE username = ? AND password_hash = ?", user.Username, user.Password)
	if err != nil || !rows.Next() {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	var userScanTo User
	rows.Scan(&userScanTo.ID, &userScanTo.Username, &userScanTo.Password)

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = userScanTo.ID
	claims["username"] = userScanTo.Username
	claims["exp"] = time.Now().Add(time.Hour * 12).Unix()
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func uploadPictureHandler(c *gin.Context) {
	var request ImageRequestBody
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	imageData, _ := base64.StdEncoding.DecodeString(request.Base64Image)
	imagePath := fmt.Sprintf("images/%s.png", uuid.New())
	err := os.WriteFile(imagePath, imageData, 0644)
	if err != nil {
		log.Fatal("Error writing image file:", err)
		return
	}

	tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")

	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Error extracting claims")
		return
	}

	userID := claims["id"]

	database, err := sql.Open("sqlite3", "db/mydb.db")
	if err != nil {
		log.Fatal(err)
	}

	statement, _ := database.Prepare("INSERT INTO images (user_id, image_path, image_url) VALUES (?, ?, ?)")
	statement.Exec(userID, imagePath, request.Base64Image)
	c.JSON(http.StatusOK, gin.H{"ok": 200})
}

func getImagesHandler(c *gin.Context) {
	database, err := sql.Open("sqlite3", "db/mydb.db")
	if err != nil {
		log.Fatal(err)
	}
	rows, err := database.Query("SELECT id, user_id, image_url from images")
	if err != nil {
		log.Fatal(err)
	}

	var images []Image
	for rows.Next() {
		var image Image
		if err := rows.Scan(&image.ID, &image.UserID, &image.ImageURL); err != nil {
			log.Fatal(err)
		}
		images = append(images, image)
	}

	c.JSON(http.StatusOK, gin.H{"images": images})

}
