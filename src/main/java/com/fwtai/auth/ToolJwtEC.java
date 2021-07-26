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
import java.util.List;

/**todo 采用openSSL生成的EC密钥*/
public class ToolJwtEC implements Serializable{

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

  public static String createToken(final Vertx vertx,final JsonObject data,final List<String> permissions){
    final JWTOptions jwtOptions = new JWTOptions();
    jwtOptions.setAlgorithm("ES256");
    jwtOptions.setAudience(getAudience());
    jwtOptions.setIssuer(issuer);
    jwtOptions.setExpiresInMinutes(45);//分钟数,有效期为xx分钟
    jwtOptions.setIgnoreExpiration(true);
    if(permissions != null && !permissions.isEmpty()){
      jwtOptions.setPermissions(permissions);
    }
    return getJwtAuth(vertx).generateToken(data,jwtOptions);
  }

  public static Future<User> authInfo(final Vertx vertx,final String token){
    final Promise<User> promise = Promise.promise();
    getJwtAuth(vertx).authenticate(new JsonObject().put("token",token))
      .onSuccess(promise::complete)
      .onFailure(promise::fail);
    return promise.future();
  }
}