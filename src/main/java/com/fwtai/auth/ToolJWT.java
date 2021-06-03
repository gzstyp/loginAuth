package com.fwtai.auth;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;

//https://vertx.io/docs/vertx-auth-jwt/java/
public final class ToolJWT{

  private final static String algorithm = "HS256";
  private final static String slat = "Www_Yinlz0Com2020DWC.cloud";

  private static JWTAuth getJwtAuth(final Vertx vertx){
    return JWTAuth.create(vertx,new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
      .setAlgorithm(algorithm)
      .setBuffer(slat)));
  }

  public static String createToken(final Vertx vertx,final JsonObject authInfo){
    return getJwtAuth(vertx).generateToken(authInfo);
  }

  //todo 好使!!!,用法:ToolJWT.authInfo(vertx,token).onSuccess(user -> {}).onFailure(err->{});
  public static Future<User> authInfo(final Vertx vertx,final String token){
    final Promise<User> promise = Promise.promise();
    getJwtAuth(vertx).authenticate(new JsonObject().put("token",token))
      .onSuccess(promise::complete)
      .onFailure(promise::fail);
    return promise.future();
  }
}