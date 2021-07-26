package com.fwtai.auth;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**todo 采用openSSL生成的EC密钥,推荐*/
public class ToolJwtEC implements Serializable{

  //如设置Token过期时间15分钟，建议更换时间设置为Token前5分钟,通过try catch 获取过期
  private final static int web_access_token = 45;//45分钟,当 refreshToken 已过期了，再判断 accessToken 是否已过期,

  /**一般更换新的accessToken小于5分钟则提示需要更换新的accessToken*/
  private final static int web_refresh_token = 40;//40分钟,仅做token的是否需要更换新的accessToken标识,小于5分钟则提示需要更换新的accessToken

  private final static int app_access_token = 60 * 24 * 20;//20天

  private final static String issuer = "贵州富翁泰科技有限责任公司(www.fwtai.com)";//jwt签发者

  private static List<String> getAudience(){
    final List<String> audiences = new ArrayList<>();
    audiences.add("www.fwtai.com");
    return audiences;
  }

  private static JWTAuth getJwtAuth(final Vertx vertx){
    return JWTAuth.create(vertx, new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("ES256")
        .setBuffer(
          "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE527X8/L2FRuqdPPeuwQcEL8ZO5eF\n" +
            "9PTCQ8QtxM4htDpuT1eC6ILg0fSZEw0cRXzpkoLn6sd+Kh2NJNUu9B8sDw==\n" +
            "-----END PUBLIC KEY-----"))
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("ES256")
        .setBuffer(
          "-----BEGIN PRIVATE KEY-----\n" +
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUW4L0kfavcIwTakK\n" +
            "jobjzaFwirSPNPd9zg8e1GDHl8yhRANCAATnbtfz8vYVG6p08967BBwQvxk7l4X0\n" +
            "9MJDxC3EziG0Om5PV4LoguDR9JkTDRxFfOmSgufqx34qHY0k1S70HywP\n" +
            "-----END PRIVATE KEY-----")
      ));
  }

  /**web端,仅作为是否需要刷新的accessToken标识,不做任何业务处理*/
  public static String expireRefreshToken(final Vertx vertx,final String userId){
    return createToken(vertx,userId,web_refresh_token,null);
  }

  /**生web端,成带认证实体且有权限的token,最后个参数是含List<String>的角色信息*/
  public static String expireAccessToken(final Vertx vertx,final String userId){
    return createToken(vertx,userId,web_access_token,null);
  }

  /**api移动端,移动端api不需要刷新的token,若过期了提示去登录重新生成token即可*/
  public static String apiAccessToken(final Vertx vertx,final String userId){
    return createToken(vertx,userId,app_access_token,null);
  }

  private static String createToken(final Vertx vertx,final String userId,final int expiresInMinutes,final List<String> permissions){
    final JWTOptions jwtOptions = new JWTOptions();
    jwtOptions.setAlgorithm("ES256");
    jwtOptions.setAudience(getAudience());
    jwtOptions.setIssuer(issuer);
    jwtOptions.setExpiresInMinutes(expiresInMinutes);//分钟数,有效期为xx分钟
    jwtOptions.setIgnoreExpiration(true);
    if(permissions != null && !permissions.isEmpty()){
      jwtOptions.setPermissions(permissions);
    }
    return getJwtAuth(vertx).generateToken(new JsonObject().put("userId",userId),jwtOptions);
  }

  /**构建web端刷新的token,移动端api不需要,若过期了提示去登录重新生成token即可*/
  public static HashMap<String,String> buildToken(final Vertx vertx,final String userId){
    final HashMap<String,String> token = new HashMap<>(2);
    token.put("refreshToken",expireRefreshToken(vertx,userId));
    token.put("accessToken",expireAccessToken(vertx,userId));
    return token;
  }

  public static Future<User> authInfo(final Vertx vertx,final String token){
    final Promise<User> promise = Promise.promise();
    getJwtAuth(vertx).authenticate(new JsonObject().put("token",token))
      .onSuccess(promise::complete)
      .onFailure(promise::fail);
    return promise.future();
  }

  public static Future<String> extractUserId(final Vertx vertx,final String token){
    final Promise<String> promise = Promise.promise();
    getJwtAuth(vertx).authenticate(new JsonObject().put("token",token))
      .onSuccess(user->promise.complete(user.attributes().getJsonObject("accessToken").getString("userId")))
      .onFailure(promise::fail);
    return promise.future();
  }
}