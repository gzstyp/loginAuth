package com.fwtai;

import com.fwtai.auth.ToolJWT;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;

public class Launcher extends AbstractVerticle {

  @Override
  public void start(final Promise<Void> startPromise) throws Exception {
    //创建HttpServer
    final HttpServer server = vertx.createHttpServer();
    //第二步,初始化|实例化 Router,若要添加跨域请求的话,随着就配置跨域
    final Router router = Router.router(vertx);

    //第三步,配置Router解析url
    router.get("/").handler(context -> {
      final JsonObject data = new JsonObject().put("userId","admin").put("role","super1");
      String token = ToolJWT.createToken(vertx,data);
      context.response()
        .putHeader("content-type","text/html;charset=utf-8")
        .end(token);
    });

    //http://127.0.0.1:88/authInfo?token=xxx
    router.get("/authInfo").handler(context -> {
      final String token = context.request().getParam("token");
      ToolJWT.authInfo(vertx,token).onSuccess(user -> {
          context.response()
          .putHeader("content-type","text/html;charset=utf-8")
          .end(user.principal().encode());
        }
      ).onFailure(err->{
        context.response()
          .putHeader("content-type","text/html;charset=utf-8")
          .end("无效的token");
      });
    });

    //第四步,将router和 HttpServer 绑定[若是使用配置文件则这样实例化,如果不配置文件则把它挪动到lambda外边即可]
    server.requestHandler(router).listen(88,http -> {
      if (http.succeeded()){
        startPromise.complete();
        System.out.println("---应用启动成功---,http://127.0.0.1:"+88);
      } else {
        System.out.println("Launcher应用启动失败,"+http.cause());
      }
    });
  }

  public static void main(final String[] args) {
    Vertx.vertx().deployVerticle(new Launcher());
  }
}