/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package compose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"
)

type CommonStrategy struct {
	oauth2.CoreStrategy
	openid.OpenIDConnectTokenStrategy
	jwt.JWTStrategy
}

func NewOAuth2HMACStrategy(config *Config, secret []byte, rotatedSecrets [][]byte) *oauth2.HMACSHAStrategy {
	return &oauth2.HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{
			GlobalSecret:         secret,
			RotatedGlobalSecrets: rotatedSecrets,
		},
		AccessTokenLifespan:   config.GetAccessTokenLifespan(),
		AuthorizeCodeLifespan: config.GetAuthorizeCodeLifespan(),
	}
}

func NewOAuth2JWTStrategy(key *rsa.PrivateKey, strategy *oauth2.HMACSHAStrategy) *oauth2.DefaultJWTStrategy {
	return &oauth2.DefaultJWTStrategy{
		JWTStrategy: &jwt.RS256JWTStrategy{
			PrivateKey: key,
		},
		HMACSHAStrategy: strategy,
	}
}

func NewOpenIDConnectStrategy(config *Config, key *rsa.PrivateKey) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		JWTStrategy: &jwt.RS256JWTStrategy{
			PrivateKey: key,
		},
		Expiry: config.GetIDTokenLifespan(),
		Issuer: config.IDTokenIssuer,
	}
}

// 依據傳入的 key 類型建立對應的 OAuth2 JWT Strategy
func NewOAuth2JWTStrategyCommon(key crypto.PrivateKey, strategy *oauth2.HMACSHAStrategy) *oauth2.DefaultJWTStrategy {
	return &oauth2.DefaultJWTStrategy{
		JWTStrategy:     newJWTStrategy(key),
		HMACSHAStrategy: strategy,
	}
}

// 依據傳入的 key 類型建立對應的 OpenID Connect JWT Strategy
func NewOpenIDConnectStrategyCommon(config *Config, key crypto.PrivateKey) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		JWTStrategy: newJWTStrategy(key),
		Expiry:      config.GetIDTokenLifespan(),
		Issuer:      config.IDTokenIssuer,
	}
}

// 依據 crypto.PrivateKey 的類型建立對應的 jwt.JWTStrategy
func newJWTStrategy(key crypto.PrivateKey) jwt.JWTStrategy {
	switch key := (interface{})(key).(type) {
	case *ecdsa.PrivateKey:
		return &jwt.ES256JWTStrategy{
			PrivateKey: key,
		}
	case *rsa.PrivateKey:
		return &jwt.RS256JWTStrategy{
			PrivateKey: key,
		}
	default:
		return &jwt.RS256JWTStrategy{
			PrivateKey: nil,
		}
	}
}
