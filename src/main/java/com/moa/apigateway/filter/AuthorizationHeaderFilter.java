package com.moa.apigateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.moa.apigateway.util.RedisUtil;

import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.config> {
	Environment env;
	RedisUtil redisUtil; //= new RedisUtil(new StringRedisTemplate());

	public AuthorizationHeaderFilter (Environment env, RedisUtil redisUtil) {
		super(config.class);
		this.env = env;
		this.redisUtil = redisUtil;
	}

	public static class config {

	}
	@Override
	public GatewayFilter apply(config config) {
		return ((exchange, chain) -> {
			ServerHttpRequest request = exchange.getRequest();

			if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange, "authorization header가 없습니다.", HttpStatus.UNAUTHORIZED);
			}

			String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
			String jwt = authorizationHeader.replace("Bearer", "");

			String isLoginUser = redisUtil.getData(jwt);

			System.out.println("\n" + jwt + "\n");
			if (!isJwtValid(jwt)) {
				return onError(exchange, "JWT Token이 유효하지 않습니다.", HttpStatus.UNAUTHORIZED);
			} else if (isLoginUser != null && isLoginUser.equals("false")) {
				return onError(exchange, "JWT Token이 유효하지 않습니다.", HttpStatus.FORBIDDEN);
			} else {
				String subject = extractMemberIdFromJwt(jwt);
				request = exchange.getRequest().mutate()
					.header("member", subject)
					.header("memberId", subject)
					.header("member-id", subject)
					.build();
			}
			return chain.filter(exchange.mutate().request(request).build());
		});
	}

	private boolean isJwtValid(String jwt) {
		boolean returnValue = true;
		String subject = null;
		try {
			subject = extractMemberIdFromJwt(jwt);
		} catch (Exception ex) {
			returnValue = false;
		}

		if (subject == null || subject.isEmpty()) {
			returnValue = false;
		}

		return returnValue;
	}

	private String extractMemberIdFromJwt(String jwt) {
		String subject = Jwts.parser().setSigningKey(env.getProperty("token.secret"))
			.parseClaimsJws(jwt).getBody()
			.getSubject();
		return subject;
	}
	private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);

		log.error(err);
		return response.setComplete();
	}
}
