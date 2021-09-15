授权获取授权码
http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=read

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