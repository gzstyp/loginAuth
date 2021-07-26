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

//todo 采用openSSL生成的RSA密钥
public final class ToolJwtRSA implements Serializable{

  private final static String issuer = "贵州富翁泰科技有限责任公司(www.fwtai.com)";//jwt签发者

  private static List<String> getAudience(){
    final List<String> audiences = new ArrayList<>();
    audiences.add("www.fwtai.com");
    return audiences;
  }

  public static JWTAuth getAuth(final Vertx vertx){
    return JWTAuth.create(vertx,new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("RS384")
        .setBuffer(
          "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz5s5qbdX09Tut+HIx8zJ\n" +
            "rwerByPrvk4uBTl+ooYOgtiJru2EPiKAF86LoJEArctzwSBsLQsOh7K66eytLQiV\n" +
            "as4uoZ1a89wQfV9KkmQOMFv0M4EjMSR7e94A0C7cTCNLL2xqlBxvJmCRZMFuwd1/\n" +
            "myUInLRSrrfNeuZRvLg7nrECYA+Zt8NntSSlOV8zmN4No1e4b4XzffsHXqIWtXZ2\n" +
            "SwMUqVADVfA+1JcmhbGzmLceVS6SuO7GnCL7d5l6/hhVs94+joo+FsvnGHMfyuyu\n" +
            "aJ2vRmK6WacAD9DCDLlGI2ejFGSFqkn4fGEDOt2FRtehapuQKRvmA8felDM71rvd\n" +
            "gQIDAQAB\n" +
            "-----END PUBLIC KEY-----"))
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("RS384")
        .setBuffer(
          "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDPmzmpt1fT1O63\n" +
            "4cjHzMmvB6sHI+u+Ti4FOX6ihg6C2Imu7YQ+IoAXzougkQCty3PBIGwtCw6Hsrrp\n" +
            "7K0tCJVqzi6hnVrz3BB9X0qSZA4wW/QzgSMxJHt73gDQLtxMI0svbGqUHG8mYJFk\n" +
            "wW7B3X+bJQictFKut8165lG8uDuesQJgD5m3w2e1JKU5XzOY3g2jV7hvhfN9+wde\n" +
            "oha1dnZLAxSpUANV8D7UlyaFsbOYtx5VLpK47sacIvt3mXr+GFWz3j6Oij4Wy+cY\n" +
            "cx/K7K5ona9GYrpZpwAP0MIMuUYjZ6MUZIWqSfh8YQM63YVG16Fqm5ApG+YDx96U\n" +
            "MzvWu92BAgMBAAECggEAe5WW5O3sjYBzPulcYXwKD3SMHisG+fmGMbwBI3SUDNYk\n" +
            "WAqyL17QS9u7iLDo64xycuP/IW00kBkYZYprqKQ0dikY30JR01sMQeXI+Y4wWB9V\n" +
            "JpfYQDfMfncwmr1ajMRxzGBIrbSjgf/4bTcs3KEjhlKsZsR9d96YpnGW9LXjX9pC\n" +
            "4oOFE5CO0heE6fX1lDr9z3yf5FAyno0ro+1xArn8+r70PQLynkEuPR+r/UR7kKON\n" +
            "eCPEXoFv4uEOUMsYbKFSUdbHwkVKKAbSjPIgTjq8uUbDEOlAB7oNMokYeuyJuY3u\n" +
            "k5l97SyKQvtiw1abApyi5PX5PTN9NYLqnsYlX/Ag8QKBgQDqRscKRUES90030kLT\n" +
            "12agoC1fxRlWJN3Xevp4IXKle6ccjLijv57gQXYhtZFcDV4mHs7zLl6jMJ4zvawG\n" +
            "AkmaceLg1+gyD1uJXdahbO1SnWs8iAZjEYiqgN6VWptamNfg0Wyt0G5usJRtUY2x\n" +
            "nNr/3OYqT2TNm/PgRBfUiWMWpQKBgQDi21siHLOK+LZ5L1DR5HbJ/4VMb0mnOAe8\n" +
            "Iu5HT2dNg65eBLlx/fVDXfVXihnd0D2FN4OFJb8+aDY7l0wyS/MrjP2RI4jC2TeJ\n" +
            "QXKZx9CNgApOhiLaNjXiqyP/xdQo7xX2VwwR8iIzX0ssVPvfEuGhzIovs0wHR2sA\n" +
            "fKhMzEpQrQKBgQDGr8IMftGCoUPWzLaqbOr33QC+US18toWCQyT7DvrpR6ZheyL4\n" +
            "lQHMFRh33EHsPNYVJFnFOhU+93OkU/75laUQm/ebUuD027t5E6F8hCH9x83zpzUr\n" +
            "fepXGDYtmotY2Xl0jIhMHRIbRByNXfX6pRnCl3iId475JYM+NuGy+dWUlQKBgGYp\n" +
            "ty7zkf/B5htJLbJ4mu55PkSf0aGW4BTf/kLrBXCpHruEkSc+4VdHVxfnP6LfBvWZ\n" +
            "fIdX6npmYBYSGuSDw60XP5I/WHW3cQVFDiEnFUrEIOAgFE4FH9tGi13Cb7tHgLKB\n" +
            "nRPv4WsVPTtnwk5BqI8/F/RHYLPee9eqS/jZ/5W5AoGAM3x/iuNyYouaVdDwKJpa\n" +
            "23X2/EmefQeSkO0T8Qz9Je8lDLx9tgCGKjJ8/wVtAcrfXJUg0euVjikFDRltN7wT\n" +
            "dej5y2CgBAUF2UfO7mWl5AWRVJ1uaV+vpYgq4dGBkFvJtJk5cD/rb0XIWgZGIyyK\n" +
            "dyeGbnaoYNywMwZoptSOpas=\n" +
            "-----END PRIVATE KEY-----")
      ));
  }

  //移动端的接口
  public static String create(final Vertx vertx,final JsonObject data){
    return create(vertx,data,null);
  }

  public static String create(final Vertx vertx,final JsonObject data,final List<String> permissions){
    final JWTOptions jwtOptions = new JWTOptions();
    jwtOptions.setAlgorithm("RS384");
    jwtOptions.setAudience(getAudience());
    jwtOptions.setIssuer(issuer);
    jwtOptions.setExpiresInMinutes(45);//分钟数,有效期为xx分钟
    jwtOptions.setIgnoreExpiration(true);
    if(permissions != null && !permissions.isEmpty()){
      jwtOptions.setPermissions(permissions);
    }
    return getAuth(vertx).generateToken(data,jwtOptions);
  }

  //todo 好使!!!,用法:ToolJWT.authInfo(vertx,token).onSuccess(user -> {}).onFailure(err->{});
  public static Future<User> authInfo(final Vertx vertx,final String token){
    final Promise<User> promise = Promise.promise();
    getAuth(vertx).authenticate(new JsonObject().put("token",token))
      .onSuccess(promise::complete)
      .onFailure(promise::fail);
    return promise.future();
  }
}