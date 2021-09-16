授权获取授权码
http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=read

当 scope =openId, 要么指定 redirect_uri， 要么配置时， redirect_uri 仅设置一个
http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=http://2afc-58-100-81-50.ngrok.io/authorized


获取 accessToken and refreshToken 
http://localhost:8080/oauth2/token?grant_type=authorization_code&code=

刷新 accessToken and refreshToken
http://localhost:8080/oauth2/token?grant_type=refresh_token&refresh_token=

废除 token
    http://localhost:8080/oauth2/revoke?token_type_hint=  &token=

client login -> get auth code -> get accessToken -> refresh accessToken

- [x] 前后端联调
- [ ] 动态 clientId/ clientSecret
- [ ] oauth2 权限问题 scope / authorities 
- [ ] OAuth2AuthorizationCodeRequestAuthenticationProvider



## port in use

lsof -t -i :8080