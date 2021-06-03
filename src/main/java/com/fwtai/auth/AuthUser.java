package com.fwtai.auth;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Authorization;

/**
 * 认证数据结构
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2021-05-31 9:43
 * @QQ号码 444141300
 * @Email service@dwlai.com
 * @官网 http://www.fwtai.com
*/
public final class AuthUser implements User{

  private final JsonObject authInfo;

  public AuthUser(final JsonObject authInfo){
    this.authInfo = authInfo;
  }

  @Override
  public JsonObject attributes(){
    return this.authInfo;
  }

  @Override
  public User isAuthorized(final Authorization authority,final Handler<AsyncResult<Boolean>> resultHandler){
    // 一直返回成功
    resultHandler.handle(Future.succeededFuture(true));
    return this;
  }

  @Override
  public JsonObject principal(){
    return this.authInfo;
  }

  @Override
  public void setAuthProvider(final AuthProvider authProvider){}
}