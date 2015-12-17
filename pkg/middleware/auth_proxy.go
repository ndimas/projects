package middleware

import (
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/log"
	m "github.com/grafana/grafana/pkg/models"
  "github.com/dgrijalva/jwt-go"
	"github.com/grafana/grafana/pkg/setting"
  "errors"
  "time"
  "fmt"
)

func initContextWithAuthProxy(ctx *Context) bool {

  log.Debug("auth_proxy.go ::: entered method")

  if !setting.AuthProxyEnabled {
    log.Info("auth_proxy.go ::: returning false")
		return false
	}

	proxyHeaderValue := ctx.Req.Header.Get(setting.AuthProxyHeaderName)

  log.Debug("auth_proxy.go ::: reading proxyHeaderValue returning %v", proxyHeaderValue)

	if len(proxyHeaderValue) == 0 {
      log.Info("auth_proxy.go ::: proxyHeaderValue returned null")
      //TODO: Redirect or Access is denied
			return false
	}

  valid, username, authorities := isValidToken(proxyHeaderValue)//isValidToken(proxyHeaderValue, func() {  })

  if ( !valid ) {
    log.Debug("auth_proxy.go ::: isValidToken returning %v", valid)

    ctx.Handle(401, "Access is denied", errors.New("Access is denied"))
    return false
  }

  log.Debug("auth_proxy.go ::: going to validate username %v and authorities %v", username, authorities)

	query := getSignedInUserQueryForProxyAuth(username)
	if err := bus.Dispatch(query); err != nil {
		if err != m.ErrUserNotFound {
			ctx.Handle(500, "Failed find user specifed in auth proxy header", err)
			return true
		}

		if setting.AuthProxyAutoSignUp {
			cmd := getCreateUserCommandForProxyAuth(proxyHeaderValue)
			if err := bus.Dispatch(cmd); err != nil {
				ctx.Handle(500, "Failed to create user specified in auth proxy header", err)
				return true
			}
			query = &m.GetSignedInUserQuery{UserId: cmd.Result.Id}
			if err := bus.Dispatch(query); err != nil {
				ctx.Handle(500, "Failed find user after creation", err)
				return true
			}
		} else {
			return false
		}
	}

	// initialize session
	if err := ctx.Session.Start(ctx); err != nil {
		log.Error(3, "Failed to start session", err)
		return false
	}

	ctx.SignedInUser = query.Result
	ctx.IsSignedIn = true
	ctx.Session.Set(SESS_KEY_USERID, ctx.UserId)

	return true
}

func getSignedInUserQueryForProxyAuth(headerVal string) *m.GetSignedInUserQuery {
	query := m.GetSignedInUserQuery{}
	if setting.AuthProxyHeaderProperty == "username" {
		query.Login = headerVal
	} else if setting.AuthProxyHeaderProperty == "email" {
		query.Email = headerVal
	} else {
		panic("Auth proxy header property invalid")
	}
	return &query
}

func getCreateUserCommandForProxyAuth(headerVal string) *m.CreateUserCommand {
	cmd := m.CreateUserCommand{}
	if setting.AuthProxyHeaderProperty == "username" {
		cmd.Login = headerVal
		cmd.Email = headerVal
	} else if setting.AuthProxyHeaderProperty == "email" {
		cmd.Email = headerVal
		cmd.Login = headerVal
	} else {
		panic("Auth proxy header property invalid")
	}
	return &cmd
}

func lookupCallback(token map[string]interface{}) (interface{}, error) {

  log.Debug("auth_proxy.go ::: entered myLookupKey for token %v", token)

  log.Debug("auth_proxy.go ::: client_id=%v, jti=%v, scope=%v, exp=%v, user_name=%v, authorities=%v",

    token["client_id"],token["jti"],token["scope"],token["exp"],token["user_name"],token["authorities"])

  var public_key string =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnGp/Q5lh0P8nPL21oMMrt2RrkT9AW5jgYwLfSUnJVc9G6uR3cXRRDCjHqWU5WYwivcF180A6CWp/ireQFFBNowgc5XaA0kPpzEtgsA5YsNX7iSnUibB004iBTfU9hZ2Rbsc8cWqynT0RyN4TP1RYVSeVKvMQk4GT1r7JCEC+TNu1ELmbNwMQyzKjsfBXyIOCFU/E94ktvsTZUHF4Oq44DBylCDsS1k7/sfZC2G5EU7Oz0mhG8+Uz6MSEQHtoIi6mc8u64Rwi3Z3tscuWG2ShtsUFuNSAFNkY7LkLn+/hxLCu2bNISMaESa8dG22CIMuIeRLVcAmEWEWH5EEforTg+QIDAQAB\n" +
  "-----END PUBLIC KEY-----"

  var public_key_byte []byte = []byte(public_key)

  return public_key_byte, nil
}

func getTime() time.Time {
  var returnTime time.Time = time.Now().Add(   time.Duration(2)*time.Hour*-1 )

  log.Debug("auth_proxy.go ::: returning new date = %v", returnTime)

  return returnTime
}

func isValidToken(inputToken string) (bool, string, interface{}) {

  if len(inputToken) == 0 {
    log.Debug("auth_proxy.go ::: nil input token found")
    return false, "", nil
  }

  jwt.TimeFunc = getTime

  token, err := jwt.Parse(inputToken, func(token *jwt.Token) (interface{}, error) {

    if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
      return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
    }

    log.Debug("auth_proxy.go ::: callback for token %v", token)

    return lookupCallback(token.Claims)
  })

  if token == nil {
    log.Debug("auth_proxy.go ::: no token found ")
    return false, "", nil
  }

  log.Debug("auth_proxy.go ::: returned token from validation token=%v errors=%v", token, err)

  if token.Valid {
    log.Debug("auth_proxy.go ::: Token Validation Success!")

    user_name   := token.Claims["user_name"].(string)
    authorities := token.Claims["authorities"]

    return true, user_name, authorities
  } else if ve, ok := err.(*jwt.ValidationError); ok {
    if ve.Errors&jwt.ValidationErrorMalformed != 0 {
      log.Debug("auth_proxy.go ::: Cannot recognize the token")
      return false, "", nil
    } else if ve.Errors&(jwt.ValidationErrorExpired |jwt.ValidationErrorNotValidYet) != 0 {
      log.Debug("auth_proxy.go ::: Token Expired or not active yet")
      return false, "", nil
    } else {
      log.Debug("auth_proxy.go ::: Couldn't handle token - Validation Error")
      return false, "", nil
    }
  } else {
    log.Debug("auth_proxy.go ::: Couldn't handle token")
    return false, "", nil
  }
}
