package token

// Unique identifier that we use to track sent and received probes.
// The token is signed and encrypted to reduce the chances
// of a replay attack

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

type TokenBuilder interface {
	GenerateToken(address string) (string, error)
	Verify(token string) (bool, error)
}

func NewJWTBuilder(hmacSecret []byte) TokenBuilder {
	return &jwtBuilder{
		hmacSecret:    hmacSecret,
		signingMethod: jwt.SigningMethodHS256,
	}
}

type jwtBuilder struct {
	hmacSecret    []byte
	signingMethod *jwt.SigningMethodHMAC
}

func (builder *jwtBuilder) GenerateToken(address string) (string, error) {
	ttime := time.Now()

	claims := jwt.MapClaims{
		"addr": address,
		"iat":  ttime.Unix(),
		"exp":  ttime.Add(time.Minute * 1).Unix(),
		"jti":  fmt.Sprintf("%d", ttime.UnixNano()),
	}

	token := jwt.NewWithClaims(builder.signingMethod, claims)
	tokenString, err := token.SignedString(builder.hmacSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (builder *jwtBuilder) Verify(token string) (bool, error) {

	keyFunk := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return builder.hmacSecret, nil
	}

	parsedToken, err := jwt.Parse(token, keyFunk)
	if err != nil {
		return false, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		// Check if the token is expired
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			return false, fmt.Errorf("token is expired")
		}

		return true, nil
	}

	return false, fmt.Errorf("invalid token")
}
