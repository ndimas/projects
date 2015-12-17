package middleware

import (
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/log"
	m "github.com/grafana/grafana/pkg/models"
  "github.com/dgrijalva/jwt-go"
	"github.com/grafana/grafana/pkg/setting"
  "errors"
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
			return false
	}

  //TODO: Validate Token
  valid := isValidToken(proxyHeaderValue)//isValidToken(proxyHeaderValue, func() {  })

  if ( !valid ) {
    log.Debug("auth_proxy.go ::: isValidToken returning %v", valid)


    ctx.Handle(401, "Access is denied", errors.New("Access is denied"))
    return false
  }

	query := getSignedInUserQueryForProxyAuth(proxyHeaderValue)
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

func myLookupKey(token interface {}) (interface{}, error) {

  log.Debug("auth_proxy.go ::: entered myLookupKey for token %v", token)

  //on error return nil, errors.New("foobar")

  return token, nil
}

func isValidToken(inputToken string) bool {

  if len(inputToken) == 0 {
    log.Debug("auth_proxy.go ::: nil input token found")
    return false
  }

  token, err := jwt.Parse(inputToken, func(token *jwt.Token) (interface{}, error) {

    log.Debug("auth_proxy.go ::: callback for token %v", token)


    return myLookupKey(token.Header["kid"])
  })

  if token == nil {
    log.Debug("auth_proxy.go ::: no token found ")
    return false
  }

  if token.Valid {
    log.Debug("auth_proxy.go ::: Token Validation Success!")
    return true
  } else if ve, ok := err.(*jwt.ValidationError); ok {
    if ve.Errors&jwt.ValidationErrorMalformed != 0 {
      log.Debug("auth_proxy.go ::: Cannot recognize the token")
      return false
    } else if ve.Errors&(jwt.ValidationErrorExpired |jwt.ValidationErrorNotValidYet) != 0 {
      log.Debug("auth_proxy.go ::: Token Expired or not active yet")
      return false
    } else {
      log.Debug("auth_proxy.go ::: Couldn't handle token")
      return false
    }
  } else {
    log.Debug("auth_proxy.go ::: Couldn't handle token")
    return false
  }
}
